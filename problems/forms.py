from django import forms

from .models import Problem, Solution


class ProblemForm(forms.ModelForm):
    class Meta:
        model = Problem
        fields = ("title", "topic", "difficulty", "statement")


class SolutionForm(forms.ModelForm):
    class Meta:
        model = Solution
        fields = ("body",)
        labels = {"body": "Your solution"}
