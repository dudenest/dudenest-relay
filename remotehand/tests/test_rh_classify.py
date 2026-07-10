import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from rh_protocol import PageState  # noqa: E402
from rh_classify import classify_text, classify_image, make_classifier  # noqa: E402

# Representative OCR blobs approximating what Tesseract yields on each Google page.
EMAIL = "Sign in\nUse your Google Account\nEmail or phone\nForgot email?\nNext"
PASSWORD = "Welcome\ndemo@example.com\nEnter your password\nShow password\nNext"
PHONE = "2-Step Verification\nGet a verification code\nEnter a phone number where you can receive"
SMS = "2-Step Verification\nEnter the code\nG-882211\nA text message with a code was sent"
CAPTCHA = "Type the text you hear or see\nI'm not a robot"
CONSENT = "Dudenest wants to access your Google Account\nAllow\nCancel"
ERR_NOACCT = "Couldn't find your Google Account\nTry again"
ERR_WRONGPW = "Wrong password. Try again or click Forgot password to reset it."


class TestClassifyText(unittest.TestCase):
    def test_email(self): self.assertEqual(classify_text(EMAIL), PageState.EMAIL)
    def test_password(self): self.assertEqual(classify_text(PASSWORD), PageState.PASSWORD)
    def test_phone(self): self.assertEqual(classify_text(PHONE), PageState.PHONE)
    def test_sms(self): self.assertEqual(classify_text(SMS), PageState.SMS)
    def test_captcha(self): self.assertEqual(classify_text(CAPTCHA), PageState.CAPTCHA)
    def test_consent(self): self.assertEqual(classify_text(CONSENT), PageState.CONSENT)
    def test_error_no_account(self): self.assertEqual(classify_text(ERR_NOACCT), PageState.ERROR)
    def test_error_wrong_password(self): self.assertEqual(classify_text(ERR_WRONGPW), PageState.ERROR)

    def test_unknown_on_blank(self):
        self.assertEqual(classify_text("Loading..."), PageState.UNKNOWN)
        self.assertEqual(classify_text(""), PageState.UNKNOWN)

    def test_case_insensitive(self):
        self.assertEqual(classify_text("ENTER YOUR PASSWORD"), PageState.PASSWORD)


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


if __name__ == "__main__":
    unittest.main()
