(() => {
    const token = new URLSearchParams(window.location.search).get("t");
    if (!token) {
        return;
    }

    const showSafeError = (title) => {
        const main = document.querySelector("main");
        if (!main) {
            return;
        }

        main.innerHTML = `
            <div class="container py-5 px-3" role="alert">
                <div class="row justify-content-center">
                    <div class="col-12 col-md-8 col-lg-6">
                        <div class="card border-0 shadow-sm p-4 text-center">
                            <h1 class="h4 text-dark mb-3">${title}</h1>
                            <p class="text-muted mb-0">The verification link is invalid, expired, or unavailable.</p>
                        </div>
                    </div>
                </div>
            </div>`;
    };

    fetch(`/api/verify-token?t=${encodeURIComponent(token)}`, {
        credentials: "same-origin",
        cache: "no-store",
        headers: { "Accept": "application/json" }
    })
        .then(async (response) => {
            if (response.ok) {
                return;
            }

            if (response.status === 410) {
                showSafeError("Verification link expired");
            } else if (response.status === 429) {
                showSafeError("Too many verification attempts");
            } else {
                showSafeError("Verification link not valid");
            }
        })
        .catch(() => {
            showSafeError("Verification unavailable");
        });
})();
