from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from .forms import ProblemForm, SolutionForm
from .models import Problem


def problem_list(request):
    topic = request.GET.get("topic")
    problems = Problem.objects.select_related("author")
    if topic:
        problems = problems.filter(topic=topic)
    return render(request, "problems/list.html", {"problems": problems, "topics": Problem.Topic.choices, "topic": topic})


def problem_detail(request, pk):
    problem = get_object_or_404(Problem.objects.select_related("author"), pk=pk)
    form = SolutionForm()
    if request.method == "POST":
        if not request.user.is_authenticated:
            return redirect("login")
        form = SolutionForm(request.POST)
        if form.is_valid():
            solution = form.save(commit=False)
            solution.problem = problem
            solution.author = request.user
            solution.save()
            return redirect(problem)
    return render(request, "problems/detail.html", {"problem": problem, "form": form})


@login_required
def problem_create(request):
    form = ProblemForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        problem = form.save(commit=False)
        problem.author = request.user
        problem.save()
        return redirect(problem)
    return render(request, "problems/form.html", {"form": form})
