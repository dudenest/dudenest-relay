import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rh_protocol import PageState  # noqa: E402
from rh_classify import classify_text, classify_image, make_classifier, classify_error  # noqa: E402

# Representative OCR blobs approximating what Tesseract yields on each Google page.
EMAIL = "Sign in\nUse your Google Account\nEmail or phone\nForgot email?\nNext"
PASSWORD = "Welcome\ndemo@example.com\nEnter your password\nShow password\nNext"
PHONE = "2-Step Verification\nGet a verification code\nEnter a phone number where you can receive"
SEND_CODE = "Verify it's you\nGet a verification code\nGoogle will send a verification code to +++ +++ +90. Standard message and data rates may apply.\nSend"
SMS = "2-Step Verification\nEnter the code\nG-882211\nA text message with a code was sent"
CAPTCHA = "Type the text you hear or see\nI'm not a robot"
CONSENT = "Dudenest wants to access your Google Account\nAllow\nCancel"
UNVERIFIED = "Google hasn't verified this app\nAdvanced\nBACK TO SAFETY"
ERR_NOACCT = "Couldn't find your Google Account\nTry again"
ERR_NOACCT_OCR = "Couldnt find his account"
ERR_WRONGPW = "Wrong password. Try again or click Forgot password to reset it."


class TestClassifyText(unittest.TestCase):
    def test_email(self): self.assertEqual(classify_text(EMAIL), PageState.EMAIL)
    def test_password(self): self.assertEqual(classify_text(PASSWORD), PageState.PASSWORD)
    def test_phone(self): self.assertEqual(classify_text(PHONE), PageState.PHONE)
    def test_send_code_to_known_phone(self): self.assertEqual(classify_text(SEND_CODE), PageState.SEND_CODE)
    def test_sms(self): self.assertEqual(classify_text(SMS), PageState.SMS)
    def test_captcha(self): self.assertEqual(classify_text(CAPTCHA), PageState.CAPTCHA)
    def test_consent(self): self.assertEqual(classify_text(CONSENT), PageState.CONSENT)
    def test_unverified_app(self): self.assertEqual(classify_text(UNVERIFIED), PageState.UNVERIFIED_APP)
    def test_error_no_account(self): self.assertEqual(classify_text(ERR_NOACCT), PageState.ERROR)
    def test_error_no_account_ocr_variant(self): self.assertEqual(classify_text(ERR_NOACCT_OCR), PageState.ERROR)
    def test_error_wrong_password(self): self.assertEqual(classify_text(ERR_WRONGPW), PageState.ERROR)

    def test_unknown_on_blank(self):
        self.assertEqual(classify_text("Loading..."), PageState.UNKNOWN)
        self.assertEqual(classify_text(""), PageState.UNKNOWN)

    def test_case_insensitive(self):
        self.assertEqual(classify_text("ENTER YOUR PASSWORD"), PageState.PASSWORD)

    def test_consent_with_line_wrapped_heading(self):
        # Real OCR wraps the heading across lines; must still be CONSENT (was misread as EMAIL
        # because 'Sign in with Google' matched and the wrapped 'wants access' did not).
        wrapped = ("Sign in with Google\ndudenest-relay wants\naccess to your Google\nAccount\n"
                   "dudenest.demo@gmail.com\nCancel  Continue")
        self.assertEqual(classify_text(wrapped), PageState.CONSENT)

    def test_phone_page_not_misread_as_sms(self):
        # PHONE page mentions 'verification code' (to receive) — must stay PHONE, not SMS.
        self.assertEqual(
            classify_text("2-Step Verification\nGet a verification code\nEnter a phone number"),
            PageState.PHONE)

    def test_oauth_callback_page_is_success(self):
        # Relay callback page shown after the token is captured — must end the session so the
        # display is freed (else a second 'Relay assisted' finds no free display).
        self.assertEqual(classify_text("Authorization complete. You can close this page."),
                         PageState.SUCCESS)

    def test_known_phone_send_code_not_misread_as_phone(self):
        self.assertEqual(classify_text("Get a verification code\nGoogle will send a verification code to +48 ***"),
                         PageState.SEND_CODE)


class TestPriority(unittest.TestCase):
    """Terminal/specific states win over the generic EMAIL 'sign in' phrase."""
    def test_wrong_password_beats_password_and_email(self):
        # A page that literally contains both 'sign in' and an error must be ERROR.
        self.assertEqual(classify_text("Sign in\nWrong password. Try again"), PageState.ERROR)

    def test_sms_beats_phone_when_code_present(self):
        self.assertEqual(classify_text("2-Step Verification\nEnter the code\nG-11"), PageState.SMS)


class TestClassifyImageInjectableOCR(unittest.TestCase):
    def test_image_uses_injected_ocr(self):
        fake_ocr = lambda png: PASSWORD  # noqa: E731 — pretend Tesseract returned this
        self.assertEqual(classify_image(b"\x89PNG...", ocr=fake_ocr), PageState.PASSWORD)

    def test_make_classifier_callable(self):
        clf = make_classifier(ocr=lambda png: EMAIL)
        self.assertEqual(clf(b"..."), PageState.EMAIL)


class TestObserverIntegration(unittest.TestCase):
    """ScrotObserver with a real classifier callable (grab mocked)."""
    def test_scrot_observer_classifies(self):
        from rh_screen import ScrotObserver
        obs = ScrotObserver(classifier=make_classifier(ocr=lambda png: SMS))
        obs.grab = lambda region=None: b"fakepng"  # avoid real scrot
        self.assertEqual(obs.observe(), PageState.SMS)


class TestClassifyError(unittest.TestCase):
    def test_wrong_password_reprompts_password(self):
        field, msg = classify_error("Wrong password. Try again or click Forgot password.")
        self.assertEqual(field, "password")
        self.assertIn("password", msg.lower())

    def test_wrong_code_reprompts_code(self):
        self.assertEqual(classify_error("Wrong code. Enter it again")[0], "code")
        self.assertEqual(classify_error("You entered an invalid code")[0], "code")

    def test_phone_error_reprompts_phone(self):
        self.assertEqual(classify_error("This phone number cannot be used for verification")[0], "phone")

    def test_no_account_reprompts_login(self):
        self.assertEqual(classify_error("Couldn't find your Google Account")[0], "login")
        self.assertEqual(classify_error("Couldnt find his account")[0], "login")

    def test_terminal_errors_return_none(self):
        self.assertIsNone(classify_error("Too many failed attempts. Try again later")[0])
        self.assertIsNone(classify_error("This account has been disabled")[0])

    def test_unknown_error_is_terminal(self):
        field, msg = classify_error("some unexpected page")
        self.assertIsNone(field)
        self.assertTrue(msg)


class TestSessionExpired(unittest.TestCase):
    """Google's idle-timeout interstitial (user took too long via the relay form)."""
    SAMPLES = [
        "Your session ended because there was no activity",
        "Your session has expired",
        "Your session timed out",
        "You've been signed out",
    ]

    def test_classifies_as_error(self):
        for t in self.SAMPLES:
            self.assertEqual(classify_text(t), PageState.ERROR, t)

    def test_is_terminal_with_restart_message(self):
        for t in self.SAMPLES:
            field, msg = classify_error(t)
            self.assertIsNone(field, t)                 # terminal — cannot recover the dead OAuth state
            self.assertIn("session expired", msg.lower(), t)


if __name__ == "__main__":
    unittest.main()
