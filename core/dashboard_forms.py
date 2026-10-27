"""Small, explicitly scoped operator forms."""

from django import forms

from .models import EmailCase, Mailbox


class CaseFilterForm(forms.Form):
    q = forms.CharField(required=False, max_length=150, label="Search",
                        widget=forms.TextInput(attrs={"class": "form-control", "placeholder": "Subject, sender, message ID"}))
    mailbox = forms.ChoiceField(required=False, label="Mailbox",
                                widget=forms.Select(attrs={"class": "form-select"}))
    verdict = forms.ChoiceField(required=False, label="Verdict",
                                choices=[("", "All verdicts"), *EmailCase.Verdict.choices],
                                widget=forms.Select(attrs={"class": "form-select"}))
    state = forms.ChoiceField(required=False, label="Processing state",
                              choices=[("", "All states"), *EmailCase.State.choices],
                              widget=forms.Select(attrs={"class": "form-select"}))
    label = forms.ChoiceField(required=False, label="Gmail label",
                              choices=[("", "All labels"), ("INBOX", "INBOX"),
                                       ("UNREAD", "UNREAD"), ("SPAM", "SPAM"),
                                       ("TRASH", "TRASH"), ("yphish", "Yphish/Suspicious")],
                              widget=forms.Select(attrs={"class": "form-select"}))
    response = forms.ChoiceField(required=False, label="Response state",
                                 choices=[("", "All responses"), ("labeled", "Labeled"),
                                          ("inbox_removed", "Removed from INBOX"),
                                          ("restored", "Restored"), ("pending", "Pending"),
                                          ("failed", "Failed action"), ("unavailable", "Unavailable"),
                                          ("none", "No action")],
                                 widget=forms.Select(attrs={"class": "form-select"}))

    def __init__(self, *args, mailboxes, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["mailbox"].choices = [("", "All mailboxes")] + [
            (str(mailbox.pk), mailbox.address) for mailbox in mailboxes
        ]


class FeedbackForm(forms.Form):
    proposed_verdict = forms.ChoiceField(
        label="Proposed verdict",
        choices=[("", "Select verdict"), (EmailCase.Verdict.LEGITIMATE, "Legitimate"),
                 (EmailCase.Verdict.SUSPICIOUS, "Suspicious"),
                 (EmailCase.Verdict.MALICIOUS, "Malicious")],
        widget=forms.Select(attrs={"class": "form-select"}),
    )
    reason = forms.CharField(min_length=10, max_length=1000, label="Reason",
                             help_text="Explain the observation. Feedback does not retrain the model.",
                             widget=forms.Textarea(attrs={"class": "form-control", "rows": 3}))


class ReviewForm(forms.Form):
    decision = forms.ChoiceField(label="Review decision",
                                 choices=[("", "Select decision"), ("approve", "Approve"),
                                          ("reject", "Reject")],
                                 widget=forms.Select(attrs={"class": "form-select"}))
    reason = forms.CharField(min_length=10, max_length=1000, label="Review reason",
                             widget=forms.Textarea(attrs={"class": "form-control", "rows": 2}))


class ResponseMailboxForm(forms.Form):
    enabled = forms.BooleanField(required=False, label="Enable automatic response",
                                 widget=forms.CheckboxInput(attrs={"class": "form-check-input"}))
    remove_inbox = forms.BooleanField(required=False, label="Remove INBOX when policy qualifies",
                                      widget=forms.CheckboxInput(attrs={"class": "form-check-input"}))

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("remove_inbox") and not cleaned.get("enabled"):
            raise forms.ValidationError("Enable automatic response before INBOX removal.")
        return cleaned
