(function bootStorefrontLab() {
  const qs = (selector) => document.querySelector(selector);
  const productGrid = qs("#productGrid");
  const searchSummary = qs("#searchSummary");
  const searchForm = qs("#searchForm");
  const searchInput = qs("#searchInput");
  const clearSearchBtn = qs("#clearSearchBtn");
  const quickFilterButtons = Array.from(document.querySelectorAll(".quick-filter-btn"));
  const commentList = qs("#commentList");
  const commentForm = qs("#commentForm");
  const commentInput = qs("#commentInput");
  const loginForm = qs("#loginForm");
  const loginStatus = qs("#loginStatus");
  const profileForm = qs("#profileForm");
  const profileResult = qs("#profileResult");
  const viewerIdInput = qs("#viewerIdInput");
  const targetIdInput = qs("#targetIdInput");

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

  function commentTemplate(entry) {
    return `
      <li>
        <div class="comment-meta">${new Date(entry.createdAt).toLocaleString()}</div>
        <div class="comment-message">${entry.message}</div>
      </li>
    `;
  }

  async function loadProducts(query) {
    const url = query ? `/lab/api/products?q=${encodeURIComponent(query)}` : "/lab/api/products";
    const response = await fetch(url);
    const data = await response.json();
    productGrid.innerHTML = data.products.map(cardTemplate).join("");
    searchSummary.innerHTML = data.searchSummary;
  }

  function toggleClearButton() {
    clearSearchBtn.hidden = !searchInput.value;
  }

  async function applySearch(query, syncInput = false) {
    const normalized = String(query || "");
    const nextUrl = normalized ? `/?q=${encodeURIComponent(normalized)}` : "/";
    window.history.replaceState({}, "", nextUrl);
    if (syncInput) {
      searchInput.value = normalized;
    }
    toggleClearButton();
    await loadProducts(normalized);
  }

  async function loadPost() {
    const response = await fetch("/lab/api/blog-post");
    const data = await response.json();
    qs("#postTitle").textContent = data.title;
    qs("#postMeta").textContent = `By ${data.author} • ${data.createdAt}`;
    qs("#postContent").textContent = data.content;
  }

  async function loadComments() {
    const response = await fetch("/lab/api/comments");
    const data = await response.json();
    commentList.innerHTML = data.comments.map(commentTemplate).join("");
  }

  searchForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    await applySearch(searchInput.value || "");
  });

  searchInput.addEventListener("input", () => {
    toggleClearButton();
  });

  searchInput.addEventListener("keydown", async (event) => {
    if (event.key === "Escape") {
      event.preventDefault();
      await applySearch("", true);
      searchInput.focus();
    }
  });

  clearSearchBtn.addEventListener("click", async () => {
    await applySearch("", true);
    searchInput.focus();
  });

  quickFilterButtons.forEach((button) => {
    button.addEventListener("click", async () => {
      const query = button.dataset.query || "";
      await applySearch(query, true);
    });
  });

  commentForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = { message: commentInput.value || "" };
    const response = await fetch("/lab/api/comments", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    commentList.innerHTML = data.comments.map(commentTemplate).join("");
    commentInput.value = "";
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
      loginStatus.textContent = data.welcome;
    } else {
      loginStatus.textContent = data.error || "Unable to sign in right now.";
    }
  });

  profileForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const viewer = viewerIdInput.value || "";
    const targetId = targetIdInput.value || "";
    const url = `/lab/api/profile/${encodeURIComponent(targetId)}?viewer=${encodeURIComponent(viewer)}`;
    const response = await fetch(url);
    const data = await response.json();
    profileResult.textContent = JSON.stringify(data, null, 2);
  });

  (async function init() {
    await loadPost();
    await loadComments();
    const params = new URLSearchParams(window.location.search);
    const q = params.get("q") || "";
    await applySearch(q, true);
  })();
})();
