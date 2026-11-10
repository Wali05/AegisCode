# expect: AEG-TAINT-SQL
def profile(request):
    username = request.GET["u"]
    users = User.objects.raw("SELECT * FROM auth_user WHERE username = '%s'" % username)
    return render(request, "profile.html", {"users": users})
