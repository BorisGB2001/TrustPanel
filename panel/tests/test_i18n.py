import json
import re
from pathlib import Path

from app import fmt, i18n

LOCALES = Path(i18n.__file__).parent / "locales"


def test_all_phrases_translated_with_same_placeholders():
    keys = i18n.extract()
    assert len(keys) > 300
    for f in LOCALES.glob("*.json"):
        cat = json.loads(f.read_text(encoding="utf-8"))
        assert cat.get("_language"), f.name
        missing = sorted(k for k in keys if k not in cat)
        assert not missing, f"{f.name}: нет перевода для {missing[:10]}"
        for k in keys:
            assert sorted(re.findall(r"\{\w+\}", k)) == sorted(re.findall(r"\{\w+\}", cat[k])), (f.name, k)


def test_switch_language_and_fallback():
    i18n.load()
    assert dict(i18n.languages())["ru"] == "Русский"
    with i18n.use("ru"):
        assert i18n.t("Clients") == "Клиенты"
        assert fmt.size(2048) == "2.0 КиБ" and fmt.duration(3720) == "1 ч 2 мин"
        assert i18n.t("Unknown phrase {x}", x=1) == "Unknown phrase 1"
    with i18n.use("xx"):                       # неизвестный язык — английский
        assert i18n.t("Clients") == "Clients" and fmt.size(2048) == "2.0 KiB"
    assert fmt.event_text("connect", json.dumps({"endpoint": "1.2.3.4"})) == "connected from 1.2.3.4"
