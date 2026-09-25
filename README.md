# PeMeO Core

## 让技术向前，让人始终在中心。

**以人为本，向善而行！**  
**People first. Guided by good.**  
**Der Mensch im Mittelpunkt. Das Gute als Kompass.**

[中文（简体）](docs/i18n/zh-CN.md) · [English](docs/i18n/en.md) · [Español](docs/i18n/es.md) · [العربية](docs/i18n/ar.md) · [हिन्दी](docs/i18n/hi.md) · [Русский](docs/i18n/ru.md) · [Français](docs/i18n/fr.md) · [Português](docs/i18n/pt.md) · [Bahasa Melayu](docs/i18n/ms.md) · [Bahasa Indonesia](docs/i18n/id.md) · [বাংলা](docs/i18n/bn.md) · [Deutsch](docs/i18n/de.md)

[共同理念 / Our purpose](PURPOSE.md) · [Language selection & translation scope](docs/LANGUAGE_POLICY.md)

*实验性开发者预览 · Experimental developer preview · Experimentelle Entwicklervorschau*

## 中文

一句话、一段经历、一次慎重的确认，背后都是一个人的生活。

当技术越来越善于理解和推断，我们更希望它学会尊重：哪些是你说过的话，哪些是系统的理解，哪些是你真正确认过的内容。每一种表达，都应有自己的来处。每一次重要的判断，都应留有追问的空间。

PeMeO 的长期愿景，是让数字记忆帮助人理解生活、保有选择，并与重要的人和事保持联系。PeMeO Core 从一件基础的事情做起：为表达、来源和确认建立清楚、可追溯的记录。

**原话，值得被认真保留。** 原始记录采用追加式存储；新的理解应有新的记录。

**理解，应该有据可循。** 协议区分原始表达、推断与确认，保留来源关系。

**确认，应该由你作出。** 本机演示通过通行密钥，将你的确认动作绑定到具体内容。确认表明该动作通过了凭据验证；内容本身是否真实，仍需另外核验。

当前提供的是供开发者用合成资料评估的记录基座。完整个人记忆、家庭助理和真实 AI 推断服务仍属于未来工作。关于管理员信任边界、尚未完成的真人测试及恢复限制，请读[已知限制](docs/KNOWN_LIMITATIONS.md)。

从[安装与验证](docs/INSTALL.md)开始，或先读我们的[共同理念](PURPOSE.md)。

## English

### As technology moves forward, people stay at the heart.

A statement, an experience, a considered confirmation: each belongs to someone's life.

As technology becomes better at interpreting and inferring, we want it to respect the difference between what you said, what a system inferred, and what you actually confirmed. Every expression should retain its origin. Every important judgment should leave room for questions.

Our long-term vision is digital memory that helps people understand their lives, retain their choices and stay connected to what matters. PeMeO Core begins with the foundation: clear, traceable records of statements, sources and confirmations.

**Your words deserve care.** Original records use append-only storage; a new interpretation belongs in a new record.

**Understanding needs a basis.** The protocol distinguishes original statements, inferences and confirmations, with references to their sources.

**Confirmation belongs with you.** The local demo uses passkeys to bind your confirmation action to specific content. It verifies the credential-backed action; the truth of the content remains a separate question.

Today this is a record core for developer evaluation with synthetic data. A complete personal memory product, household assistant and real-model inference service remain future work. Read the [known limitations](docs/KNOWN_LIMITATIONS.md), including administrator trust, incomplete human acceptance and recovery limitations, then [install and evaluate](docs/INSTALL.md).

## Deutsch

### Technologie entwickelt sich weiter. Der Mensch bleibt im Mittelpunkt.

Eine Aussage, ein Erlebnis, eine bewusste Bestätigung: Dahinter steht immer das Leben eines Menschen.

Je besser Technologie interpretieren und Schlussfolgerungen ziehen kann, desto wichtiger ist uns ein sorgfältiger Umgang damit: Was hast du selbst gesagt? Was hat ein System daraus abgeleitet? Was hast du tatsächlich bestätigt? Jede Aussage sollte ihre Herkunft behalten. Bei wichtigen Einschätzungen muss Raum für Rückfragen bleiben.

Unsere langfristige Vision ist ein digitales Gedächtnis, das Menschen hilft, ihr Leben besser zu verstehen, selbstbestimmt zu entscheiden und mit dem verbunden zu bleiben, was ihnen wichtig ist. PeMeO Core beginnt bei der Grundlage: klaren, nachvollziehbaren Aufzeichnungen über Aussagen, Quellen und Bestätigungen.

**Deine Worte verdienen Sorgfalt.** Ursprüngliche Datensätze werden nur ergänzt. Eine neue Interpretation erhält einen neuen Datensatz.

**Verständnis braucht eine Grundlage.** Das Protokoll unterscheidet ursprüngliche Aussagen, Schlussfolgerungen und Bestätigungen und hält Quellenbezüge fest.

**Deine Bestätigung bleibt deine Entscheidung.** Die lokale Demo verbindet eine Passkey-Bestätigung mit einem konkreten Inhalt. Geprüft wird die mit dem Zugangsnachweis bestätigte Handlung; der Wahrheitsgehalt des Inhalts ist eine eigene Frage.

Heute ist dies eine Grundlage für Entwickler, die mit synthetischen Daten arbeiten. Ein vollständiges persönliches Gedächtnisprodukt, ein Haushaltsassistent und ein Dienst mit echter Modellinferenz sind zukünftige Vorhaben. Bitte lies die [bekannten Grenzen](docs/KNOWN_LIMITATIONS.md), einschließlich des Vertrauens in Administratoren, unvollständiger manueller Tests und fehlender Wiederherstellung, sowie die [Installationsanleitung](docs/INSTALL.md).

## Developer entry points

The current implementation includes Protocol v0.1 schema and business-invariant validation, PostgreSQL append-only protections for ordinary roles, rebuildable projections, transactional ingestion and a localhost HTTPS passkey confirmation demo. Administrators and the service process remain trusted. The CLI validates datasets; it is not a general authenticated write API.

- [Install and test](docs/INSTALL.md)
- [Capabilities and known limitations](docs/KNOWN_LIMITATIONS.md)
- [Validation boundaries](docs/VALIDATION.md)
- [Security reporting status](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Purpose in source code](src/ecom_backend/purpose.py)

Package version is 0.1.1; Protocol v0.1 and schema 0.1.0 remain frozen. This is an experimental, source-only developer preview. A working name does not establish trademark clearance. For any distributed archive, consult its separately published SHA-256-bound release record for actual installation, CI and security-reporting status; this source snapshot alone does not certify those external steps.

Project-authored material uses [Apache-2.0](LICENSE). Third-party terms remain their own; see [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES.md). Our purpose expresses how we choose to build; it adds no usage restriction to the license.
