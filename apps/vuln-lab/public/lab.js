(function bootMinimalLab() {
  const qs = (selector) => document.querySelector(selector);
  const productGrid = qs("#productGrid");
  const searchSummary = qs("#searchSummary");
  const searchForm = qs("#searchForm");
  const searchInput = qs("#searchInput");
  const loginForm = qs("#loginForm");
  const loginStatus = qs("#loginStatus");

  function cardTemplate(product) {
    return `
      <article class="product-card">
        <span class="badge">${product.badge}</span>
        <h3>${product.name}</h3>
        <p>${product.category}</p>
        <strong>$${product.price}</strong>
      </article>
    `;
  }

  async function loadProducts(query) {
    const url = query ? `/lab/api/products?q=${encodeURIComponent(query)}` : "/lab/api/products";
    const response = await fetch(url);
    const data = await response.json();
    productGrid.innerHTML = data.products.map(cardTemplate).join("");
    searchSummary.textContent = data.searchSummary || "";
  }

  async function applySearch(query) {
    const normalized = String(query || "");
    const nextUrl = normalized ? `/?q=${encodeURIComponent(normalized)}` : "/";
    window.history.replaceState({}, "", nextUrl);
    searchInput.value = normalized;
    await loadProducts(normalized);
  }

  searchForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await applySearch(searchInput.value || "");
  });

  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = {
      username: qs("#loginUsername").value || "",
      password: qs("#loginPassword").value || "",
    };
    const response = await fetch("/lab/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (response.ok) {
      loginStatus.textContent = data.welcome || "Signed in.";
    } else {
      loginStatus.textContent = data.error || "Sign-in failed.";
    }
  });

  (async function init() {
    const params = new URLSearchParams(window.location.search);
    const q = params.get("q") || "";
    await applySearch(q);
  })();
})();
