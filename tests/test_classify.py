from honeypot.classify import rules


def test_labels_the_classic_scripts():
    cases = {
        "This is the IRS, an arrest warrant has been filed against you for back taxes.":
            "government_impersonation",
        "Calling about your vehicle warranty — this is a final notice about your car.":
            "auto_warranty",
        "I'm from Microsoft support, your computer is infected. Install AnyDesk please.":
            "tech_support",
        "Your package could not be delivered, confirm your address with USPS tracking.":
            "delivery_phish",
        "We detected an unauthorized charge; verify your identity with the one-time code.":
            "bank_or_payment_fraud",
    }
    for text, expected in cases.items():
        result = rules.classify(text)
        assert result.category == expected, (text, result)
        assert result.confidence >= 0.5


def test_dead_air_is_a_probe_not_a_scam():
    assert rules.classify("").category == "robocall_probe"
    assert rules.classify("  beep  ").category == "robocall_probe"


def test_unremarkable_speech_is_not_forced_into_a_category():
    result = rules.classify(
        "Hi, it's Dana from the dentist confirming your cleaning on Thursday at two."
    )
    assert result.category == "unknown"
    assert result.confidence < 0.5


def test_confidence_is_bounded():
    loud = "IRS arrest warrant back taxes immediately do not hang up gift card final notice"
    assert 0.0 < rules.classify(loud).confidence <= 0.95


def test_every_signal_category_is_in_the_shared_label_set():
    assert set(rules._SIGNALS) <= set(rules.CATEGORIES)
