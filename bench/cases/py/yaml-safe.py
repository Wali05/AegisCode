# expect: none
def read_config(path):
    with open("config.yml") as fh:
        return yaml.safe_load(fh)
