from django.conf import settings
from django.db import models
from django.urls import reverse


class Problem(models.Model):
    class Topic(models.TextChoices):
        NUMBER_THEORY = "number-theory", "Number theory"
        ALGEBRA = "algebra", "Algebra"
        ANALYSIS = "analysis", "Analysis"
        GEOMETRY = "geometry", "Geometry"
        COMBINATORICS = "combinatorics", "Combinatorics"
        PROBABILITY = "probability", "Probability"

    class Difficulty(models.IntegerChoices):
        EXERCISE = 1, "Exercise"
        OLYMPIAD = 2, "Olympiad"
        RESEARCH = 3, "Research-level"

    title = models.CharField(max_length=200)
    statement = models.TextField(help_text="Markdown-ish text; use $...$ or $$...$$ for LaTeX.")
    topic = models.CharField(max_length=32, choices=Topic.choices)
    difficulty = models.IntegerField(choices=Difficulty.choices, default=Difficulty.EXERCISE)
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="problems")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        return reverse("problems:detail", args=[self.pk])


class Solution(models.Model):
    problem = models.ForeignKey(Problem, on_delete=models.CASCADE, related_name="solutions")
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="solutions")
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"Solution to {self.problem} by {self.author}"
