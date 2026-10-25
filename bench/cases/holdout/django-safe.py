# expect: none
def detail(request):
    pk = int(request.GET["id"])
    return Item.objects.raw("SELECT * FROM items WHERE id = %s", [pk])
