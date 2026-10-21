"""Generate email candidates without making unsupported breach claims."""


class Email:
    def __init__(self, config, permutations_list):
        settings = config["plateform"]["email"]
        self.domains = settings["domains"]
        self.format = settings["format"]
        self.permutations_list = list(permutations_list)

    def possible_emails(self):
        return sorted({
            self.format.format(permutation=permutation.lower(), domain=domain.lower())
            for domain in self.domains
            for permutation in self.permutations_list
        })

    def search(self):
        # pwnedpasswords checks PASSWORDS, not email breach exposure.
        return {"accounts": [
            {"value": address, "breached": None, "status": "unverified_candidate"}
            for address in self.possible_emails()
        ]}
