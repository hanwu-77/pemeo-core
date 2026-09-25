import pytest

from ecom_backend.ingestion_json import InputRejected, canonical, digest, parse, records


def test_jcs_rfc_number_serialization_vector():
    # RFC 8785 section 3.2.2: actual JCS number formatting, not sorted json.dumps.
    assert canonical({'numbers':[333333333.33333329,1e30,4.50,2e-3,1e-27]}) == b'{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}'


def test_jcs_utf16_property_order_vector():
    value={'\ufb33':1,'\U0001f600':2,'\u20ac':3,'\r':4,'1':5,'\u0080':6,'\u00f6':7}
    assert list(parse(canonical(value))) == ['\r','1','\u0080','\u00f6','\u20ac','\U0001f600','\ufb33']


def test_same_semantic_number_and_key_order_same_digest():
    assert digest('request',parse(b'{"b":1.0,"a":2}')) == digest('request',parse(b'{"a":2,"b":1}'))


@pytest.mark.parametrize('raw', [b'{"a":1,"a":2}',b'{"x":{"a":1,"a":2}}',b'NaN',b'Infinity',
    b'-Infinity',b'1e400',b'9007199254740992',b'1.0000000000000001',b'1e-400',b'"\\ud800"',b'"\xff"'])
def test_reject_ambiguous_or_lossy_input(raw):
    with pytest.raises(InputRejected): parse(raw)


@pytest.mark.parametrize('value',[{'a':None},{},['a','b'],['b','a'],'e\u0301','é'])
def test_jcs_preserves_content_distinctions(value):
    assert parse(canonical(value)) == value


def test_null_missing_array_order_unicode_remain_different():
    assert digest('x',{}) != digest('x',{'a':None})
    assert digest('x',[1,2]) != digest('x',[2,1])
    assert digest('x','é') != digest('x','e\u0301')


@pytest.mark.parametrize('raw',[b'[]',b'{}',b'[1]',b'['+b','.join([b'{}']*33)+b']',b' '*1048577])
def test_ingestion_resource_limits(raw):
    with pytest.raises(InputRejected): records(raw)
