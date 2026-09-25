"""Real signature verification; no injectable success/UV booleans or test bypass."""
from dataclasses import dataclass
import base64
import json
from urllib.parse import urlsplit

from webauthn import (generate_authentication_options, generate_registration_options,
                      options_to_json, verify_authentication_response, verify_registration_response)
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                                     ResidentKeyRequirement, UserVerificationRequirement)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.parse_cbor import parse_cbor
from .ingestion import IngestionError
from .ingestion_json import parse

VERSION = 'pemeo-webauthn-3.0.0-v1'
MAX_RESPONSE = 65536


def decode(value):
    if not isinstance(value, str) or len(value)>MAX_RESPONSE or '=' in value:
        raise ValueError('invalid base64url')
    decoded=base64.b64decode(value+'='*((-len(value))%4),altchars=b'-_',validate=True)
    if encode(decoded)!=value:
        raise ValueError('noncanonical base64url')
    return decoded


def encode(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


@dataclass(frozen=True)
class Credential:
    external_id: bytes
    public_key: bytes
    sign_count: int
    backup_eligible: bool
    backed_up: bool


class WebAuthnVerifier:
    def __init__(self, origin):
        parsed=urlsplit(origin)
        if parsed.scheme!='https' or parsed.hostname!='localhost' or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            raise ValueError('An exact HTTPS localhost origin is required')
        if origin != 'https://localhost'+(':'+str(parsed.port) if parsed.port else ''):
            raise ValueError('Noncanonical origin')
        self.origin=origin
        self.rp_id='localhost'

    @staticmethod
    def _input(raw, expected_handle=None):
        if not isinstance(raw,bytes) or len(raw)>MAX_RESPONSE:
            raise ValueError('response too large')
        body=parse(raw)
        if not isinstance(body,dict) or body.get('type')!='public-key':
            raise ValueError('credential type')
        response=body.get('response')
        if not isinstance(response,dict) or not isinstance(body.get('rawId'),str):
            raise ValueError('credential structure')
        client=parse(decode(response.get('clientDataJSON')))
        if not isinstance(client,dict):
            raise ValueError('client data structure')
        if client.get('crossOrigin',False) is not False or 'topOrigin' in client:
            raise ValueError('cross origin forbidden')
        handle=response.get('userHandle')
        if handle is not None and (expected_handle is None or decode(handle)!=expected_handle):
            raise ValueError('user handle mismatch')
        return body

    def registration_options(self, challenge, handle, exclude=()):
        options=generate_registration_options(rp_id=self.rp_id,rp_name='PeMeO',user_name='PeMeO owner',
            user_id=handle,challenge=challenge,timeout=60000,
            supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,user_verification=UserVerificationRequirement.REQUIRED),
            exclude_credentials=[PublicKeyCredentialDescriptor(id=x) for x in exclude])
        return json.loads(options_to_json(options))

    def authentication_options(self, challenge, allowed):
        options=generate_authentication_options(rp_id=self.rp_id,challenge=challenge,timeout=60000,
            allow_credentials=[PublicKeyCredentialDescriptor(id=x) for x in allowed],
            user_verification=UserVerificationRequirement.REQUIRED)
        return json.loads(options_to_json(options))

    def register(self, raw, challenge):
        try:
            body=self._input(raw)
            result=verify_registration_response(credential=body,expected_challenge=challenge,
                expected_rp_id=self.rp_id,expected_origin=self.origin,
                require_user_presence=True,require_user_verification=True,
                supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256])
            return Credential(result.credential_id,result.credential_public_key,result.sign_count,
                result.credential_device_type.value=='multi_device',result.credential_backed_up)
        except (WebAuthnException, ValueError) as exc:
            # Expected invalid input is rejected; unexpected implementation errors propagate.
            raise IngestionError('registration_verification_failed') from exc

    def authenticate(self, raw, challenge, credential, handle):
        try:
            body=self._input(raw,handle)
            if decode(body['rawId'])!=credential.external_id:
                raise ValueError('credential mismatch')
            # The selected profile accepts COSE ES256/P-256 keys only. The
            # library decoder assumes a mapping; reject corrupt stored shapes
            # before that decoder, without swallowing arbitrary TypeError.
            public=parse_cbor(credential.public_key)
            if (not isinstance(public,dict) or public.get(1)!=2 or public.get(3)!=-7
                or public.get(-1)!=1 or any(not isinstance(public.get(i),bytes)
                    or len(public[i])!=32 for i in (-2,-3))):
                raise ValueError('invalid ES256 public key structure')
            result=verify_authentication_response(credential=body,expected_challenge=challenge,
                expected_rp_id=self.rp_id,expected_origin=self.origin,
                credential_public_key=credential.public_key,
                # For registered multi-device keys the counter is telemetry, not
                # a clone detector. One-use server challenges prevent replay.
                credential_current_sign_count=0 if credential.backup_eligible else credential.sign_count,
                require_user_verification=True)
            eligible=result.credential_device_type.value=='multi_device'
            if eligible!=credential.backup_eligible:
                raise ValueError('backup eligibility changed')
            return Credential(result.credential_id,credential.public_key,
                max(credential.sign_count,result.new_sign_count),eligible,result.credential_backed_up)
        except (WebAuthnException, ValueError) as exc:
            raise IngestionError('assertion_verification_failed') from exc
