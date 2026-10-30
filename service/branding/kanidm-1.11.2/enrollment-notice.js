(() => {
  const portalUrl = __IDENTITY_PORTAL_URL__;
  const recoveryUrl = portalUrl + "/recover";
  const identityDomain = __IDENTITY_DOMAIN__.toLowerCase();
  const privateDomain = "internal.slugsec.club";
  const identityDisplays = new WeakMap();
  let credentialsSaved = false;

  function shortIdentity(value) {
    const at = value.indexOf("@");

    return at > 0 && value.slice(at + 1).toLowerCase() === identityDomain
      ? value.slice(0, at) : value;
  }

  function displayIdentityInput(input) {
    const value = shortIdentity(input.value);
    let display = identityDisplays.get(input);

    if (value === input.value) {
      if (display) {
        for (const label of display.labels)
          label.htmlFor = input.id;

        input.hidden = display.hidden;
        display.output.remove();
        identityDisplays.delete(input);
      }

      return;
    }

    if (!display) {
      const output = document.createElement("output");
      output.className = input.className;

      const labels = [...input.labels];

      if (input.id) {
        output.id = input.id + "-display";

        for (const label of labels)
          label.htmlFor = output.id;
      }

      display = { output, labels, hidden: input.hidden };
      identityDisplays.set(input, display);
      input.before(output);
      input.hidden = true;
    }

    display.output.value = value;
  }

  function shortenIdentityDisplays() {
    for (const notice of document.querySelectorAll("main .alert-info")) {
      const reauth = /^(\s*Reauthenticating as )(\S+)( to access[\s\S]*)$/.exec(notice.textContent);

      if (reauth)
        notice.textContent = reauth[1] + shortIdentity(reauth[2]) + reauth[3];
    }

    for (const paragraph of document.querySelectorAll("main#main p")) {
      const identity = /^\s*SPN:\s*(\S+)\s*$/.exec(paragraph.textContent);

      if (identity)
        paragraph.textContent = "Username: " + shortIdentity(identity[1]);
    }

    for (const nav of document.querySelectorAll('nav[aria-label="breadcrumb"]')) {
      if (!nav.querySelector('a[href="/ui/admin/persons"]'))
        continue;

      const current = nav.querySelector('[aria-current="page"]');

      if (current)
        current.textContent = shortIdentity(current.textContent.trim());
    }

    for (const group of document.querySelectorAll('li[id^="personGroup"] > div.d-flex')) {
      group.textContent = shortIdentity(group.textContent.trim());
    }

    for (const input of document.querySelectorAll('#personspn[readonly], #personmanaged_by[readonly], #members input[name="member"][readonly]')) {
      displayIdentityInput(input);
    }
  }

  function loginName(value) {
    const trimmed = value.trim();
    const schoolEmail = /^([a-z][a-z0-9_-]{2,31})@ucsc\.edu$/i.exec(trimmed);

    return schoolEmail ? schoolEmail[1].toLowerCase() : trimmed;
  }

  function applyAuthLayout() {
    const main =
      document.querySelector(
        'main.form-signin, main.shell:has(> .masthead), main.shell:has(form[action="/ui/oauth2/consent"])',
      ) ||
      [...document.querySelectorAll("main#main, main#cred-reset-form")].find(
        (element) =>
          element.querySelector(
            ":scope > img.kanidm_logo, :scope > center > img",
          ),
      );

    if (!main)
      return;

    document.body.classList.add("identity-auth");
    document.body.classList.remove("flex-column", "d-flex", "h-100");
    main.classList.remove(
      "form-signin",
      "m-auto",
      "align-items-center",
      "d-flex",
      "flex-column",
    );
    main.classList.add("shell");

    const image = main.querySelector(":scope > img, :scope > center > img");
    const heading = main.querySelector(":scope > h3, :scope > center > h2");

    if (image && heading) {
      heading.textContent = "Slug Security - Authentication";

      const header = document.createElement("header");
      header.className = "masthead";

      const brand = document.createElement("a");
      brand.className = "brand";
      brand.href = "/ui/login";
      brand.setAttribute("aria-label", heading.textContent + " home");
      image.src = "/ui/images/domain";

      const tagline = document.createElement("span");
      tagline.className = "tagline";
      tagline.textContent = "Cyber @ UC Santa Cruz";
      brand.append(image, heading, tagline);
      header.append(brand);
      main.prepend(header);
    }

    let card = main.querySelector(":scope > .card");

    if (!card) {
      const content = [...main.children].filter(
        (element) => !element.matches(".masthead"),
      );
      const body = content.length === 1 && content[0].tagName === "DIV"
        ? content[0] : document.createElement("div");

      if (body !== content[0])
        body.append(...content);

      body.classList.add("card-body", "p-4");
      card = document.createElement("div");
      card.className = "card";
      card.append(body);
      main.append(card);
    }

    for (const link of card.querySelectorAll("a:has(> button)")) {
      const button = link.querySelector(":scope > button");
      link.className = button.className;
      link.textContent = button.textContent.trim();
    }

    for (const button of card.querySelectorAll("button.btn-primary")) {
      button.classList.add("w-100");
    }

    if (card.querySelector('form[action="/ui/login/mech_choose"]')) {
      for (const container of card.querySelectorAll(".container")) {
        container.classList.remove("container");
      }
    }

    for (const actions of card.querySelectorAll("p.d-flex:has(> .btn)")) {
      actions.className = "auth-actions";

      const primary = actions.querySelector(":scope > .btn-primary");

      if (primary)
        actions.prepend(primary);
    }

    for (const link of card.querySelectorAll('.card-body > a:is([href="/ui"], [href="/ui/"])')) {
      link.classList.add("btn", "btn-primary", "w-100");
    }

    for (const paragraph of card.querySelectorAll("p")) {
      if (paragraph.textContent.includes("invalid credential state")) {
        paragraph.textContent = "Sign in again";
      }

      if (
        paragraph.textContent.trim().startsWith("Operation ID:") &&
        !paragraph.closest("details")
      ) {
        const details = document.createElement("details");
        details.className = "help";

        const summary = document.createElement("summary");
        summary.textContent = "Details";
        paragraph.before(details);
        details.append(summary, paragraph);
      }
    }

    const failed = [...card.querySelectorAll("h1, h2, h3")].find(
      (element) => ["Login Failed", "Sign-in failed"].includes(element.textContent.trim()),
    );

    if (failed) {
      if (failed.tagName !== "H1") {
        const title = document.createElement("h1");
        title.className = "h2";
        title.textContent = "Sign-in failed";
        failed.replaceWith(title);
        window.scrollTo(0, 0);
      }

      const back = card.querySelector('a[href="/ui/login"]');

      if (back) {
        back.className = "btn btn-primary";
        back.textContent = "Return to Login";

        if (!card.querySelector(`a[href="${recoveryUrl}"]`)) {
          const actions = document.createElement("div");
          actions.className = "auth-actions mt-3";

          const recover = document.createElement("a");
          recover.className = "btn btn-secondary";
          recover.href = recoveryUrl;
          recover.textContent = "Reset password";
          back.before(actions);
          actions.append(back, recover);
        }
      }
    }

    if (credentialsSaved && card.querySelector('form[action="/ui/login/begin"]')) {
      let notice = [...card.querySelectorAll(".alert-danger")].find(
        (element) => element.textContent.trim() === "Session Expired",
      );

      if (!notice) {
        notice = document.createElement("div");
        card.querySelector('label[for="username"]').before(notice);
      }

      notice.className = "alert alert-success";
      notice.setAttribute("role", "status");
      notice.textContent = "Credentials saved. Sign in again";
      credentialsSaved = false;
    }

    document.body.querySelector(":scope > footer")?.remove();
  }

  function simplifyLogin() {
    applyAuthLayout();

    const form = document.querySelector("form#login");

    if (!form)
      return;

    const code = form.querySelector("#totp");

    if (code && code.type !== "hidden" && !code.classList.contains("d-none")) {
      const card = form.closest(".card");

      if (!card.querySelector("h1")) {
        const title = document.createElement("h1");
        title.className = "h2";
        title.textContent = "Verify your authenticator";
        card.querySelector(":scope > .card-body").prepend(title);
      }

      const label = form.querySelector('label[for="totp"]');

      if (label)
        label.textContent = "Authenticator code";

      form.querySelector('button[type="submit"]').textContent = "Sign in";

      return;
    }

    const password = form.querySelector('input[name="password"]');

    if (form.getAttribute("action") === "/ui/login/pw") {
      if (password?.defaultValue && !form.dataset.identitySubmitted) {
        form.dataset.identitySubmitted = "true";
        form.requestSubmit();
      } else if (password && !password.defaultValue) {
        const card = form.closest(".card");

        if (!card.querySelector("h1")) {
          const title = document.createElement("h1");
          title.className = "h2";
          title.textContent = "Confirm your password";
          card.querySelector(":scope > .card-body").prepend(title);
        }

        form.querySelector('button[type="submit"]').textContent = "Sign in";
      }

      return;
    }

    if (form.getAttribute("action") !== "/ui/login/begin" || !password)
      return;

    form.querySelector(".form-switch")?.remove();

    const usernameLabel = form.parentElement.querySelector(
      'label[for="username"]',
    );

    if (usernameLabel)
      usernameLabel.textContent = "Username";

    if (document.getElementById("identity-create-account"))
      return;

    const title = document.createElement("h1");
    title.className = "h2";
    title.textContent = "Sign in";
    form.parentElement.prepend(title);

    const label = document.createElement("label");
    label.htmlFor = password.id;
    label.className = "form-label";
    label.textContent = "Password";

    const field = document.createElement("div");
    field.className = "input-group mb-3";
    password.before(label, field);
    password.classList.remove("d-none");
    password.classList.add("form-control");
    field.append(password);

    const recover = document.createElement("a");
    recover.className = "d-block text-end small mb-3";
    recover.href = recoveryUrl;
    recover.textContent = "Forgot password?";
    field.after(recover);

    const submit = form.querySelector('button[type="submit"]');
    submit.textContent = "Sign in";
    submit.classList.add("w-100");

    const create = document.createElement("a");
    create.id = "identity-create-account";
    create.href = portalUrl + "/join";
    create.className = "btn btn-secondary";
    create.textContent = "Create an account";

    const actions = document.createElement("div");
    actions.className = "auth-actions";

    const wrapper = submit.parentElement;
    actions.append(submit, create);

    if (wrapper !== form && !wrapper.children.length)
      wrapper.remove();

    form.append(actions);

    const username = form.querySelector('input[name="username"]');

    if (username) {
      form.addEventListener(
        "submit",
        () => {
          username.value = loginName(username.value);
        },
        true,
      );
    }
  }

  function showConsentProfile() {
    const form = document.querySelector('form[action="/ui/oauth2/consent"]');

    if (!form || form.dataset.identityConsent)
      return;

    const card = form.closest(".card");
    const information = form.previousElementSibling;

    if (!card || information?.tagName !== "DIV")
      return;

    let profile;

    try {
      profile = JSON.parse(information.dataset.identityConsentClaims);

      if (!profile || typeof profile !== "object" || Array.isArray(profile))
        throw new Error("Shared account details unavailable");
    } catch {
      form.dataset.identityConsent = "unavailable";

      return;
    }

    const heading = card.querySelector(":scope > .card-body > h2");

    if (heading) {
      const title = document.createElement("h1");
      title.className = "h2";
      title.textContent = heading.textContent
        .trim()
        .replace(/^Consent to Proceed to /, "Continue to ");
      heading.replaceWith(title);
    }

    const labels = new Map([
      ["name", "Name"],
      ["preferred_username", "Username"],
      ["email", "Email"],
      ["updated_at", "Profile updated"],
      ["groups", "Groups"],
      ["ssh_publickeys", "SSH public keys"],
    ]);
    const values = document.createElement("dl");
    values.className = "profile-details";

    for (const [claim, value] of Object.entries(profile)) {
      if (["email_verified", "scopes"].includes(claim))
        continue;

      const row = document.createElement("div");
      const term = document.createElement("dt");
      term.textContent = labels.get(claim) || claim;

      const description = document.createElement("dd");
      const updatedAt =
        claim === "updated_at" && typeof value === "number"
          ? new Date(value * 1000)
          : null;

      if (updatedAt && !Number.isNaN(updatedAt.getTime())) {
        const time = document.createElement("time");
        time.dateTime = updatedAt.toISOString();
        time.textContent = new Intl.DateTimeFormat(undefined, {
          year: "numeric",
          month: "short",
          day: "numeric",
          hour: "numeric",
          minute: "2-digit",
          timeZoneName: "short",
        }).format(updatedAt);
        description.append(time);
      } else if (Array.isArray(value)) {
        description.textContent = value
          .map((item) => {
            if (typeof item !== "string")
              return JSON.stringify(item);

            return claim === "groups" ? shortIdentity(item) : item;
          })
          .join(", ");
      } else if (typeof value === "string") {
        description.textContent = claim === "preferred_username" ? shortIdentity(value) : value;
      } else {
        description.textContent = JSON.stringify(value);
      }

      row.append(term, description);
      values.append(row);
    }

    const details = document.createElement("details");
    details.className = "consent-json";

    const summary = document.createElement("summary");
    summary.textContent = "Shared data (JSON)";

    const pre = document.createElement("pre");
    const code = document.createElement("code");
    code.textContent = JSON.stringify(profile, null, 2);
    pre.append(code);
    details.append(summary, pre);
    information.replaceChildren(values, details);
    form.dataset.identityConsent = "ready";
  }

  function simplifyTotpSetup() {
    const info = document.getElementById("totpInfo");
    const form = document.querySelector("#newTotpForm > form");

    if (!info || !form)
      return;

    info.parentElement.classList.add("col-lg-8");
    form.classList.remove("row", "g-2", "pb-3");

    for (const [id, text] of [
      ["new-totp-name", "Authenticator name"],
      ["new-totp-check", "Authenticator code"],
    ]) {
      const input = form.querySelector(`#${id}`);
      const label = form.querySelector(`label[for="${id}"]`);

      if (!input || !label)
        continue;

      label.textContent = text;

      if (input.parentElement === form) {
        const field = document.createElement("div");
        field.className = "mb-3";
        label.before(field);
        field.append(label, input);
      }
    }

    const code = form.querySelector("#new-totp-check");

    if (code)
      code.autocomplete = "one-time-code";

    const feedback = form.querySelector("#neq-totp-validation-feedback");

    if (feedback) {
      feedback.textContent = feedback.textContent.trim();
      feedback.className = document.getElementById("totp-submit")?.classList.contains("btn-warning")
        ? "alert alert-warning" : "invalid-feedback d-block mb-3";
      feedback.setAttribute("role", "alert");

      for (const input of form.querySelectorAll(".is-invalid")) {
        input.setAttribute("aria-invalid", "true");
        input.setAttribute("aria-describedby", feedback.id);
      }
    }

    const rawUri = info.querySelector(":scope > code");

    if (!rawUri?.textContent.startsWith("otpauth://totp/"))
      return;

    const uri = new URL(rawUri.textContent.trim());
    const secret = uri.searchParams.get("secret");
    const qr = info.querySelector(":scope > div > svg");

    if (!secret || !qr)
      return;

    if (!qr.hasAttribute("viewBox")) {
      qr.setAttribute("viewBox", `0 0 ${qr.width.baseVal.value} ${qr.height.baseVal.value}`);
    }

    qr.setAttribute("width", "224");
    qr.setAttribute("height", "224");
    qr.setAttribute("role", "img");
    qr.setAttribute("aria-label", "Authenticator setup QR code");
    qr.classList.add("mw-100", "h-auto");

    const qrField = document.createElement("div");
    qrField.className = "mb-2";
    qrField.append(qr);

    const app = document.createElement("p");
    app.className = "mb-3";

    const link = document.createElement("a");
    link.href = uri.href;
    link.textContent = "Open in authenticator app";
    app.append(link);

    const manual = document.createElement("details");
    manual.className = "mb-4";

    const summary = document.createElement("summary");
    summary.textContent = "Enter setup key manually";

    const label = document.createElement("label");
    label.className = "form-label mt-3";
    label.htmlFor = "totp-setup-key";
    label.textContent = "Setup key";

    const field = document.createElement("div");
    field.className = "input-group";

    const input = document.createElement("input");
    input.id = label.htmlFor;
    input.type = "text";
    input.readOnly = true;
    input.autocomplete = "off";
    input.spellcheck = false;
    input.value = secret;
    input.className = "form-control font-monospace";
    input.addEventListener("focus", () => input.select());

    const copy = document.createElement("button");
    copy.type = "button";
    copy.className = "btn btn-outline-secondary";
    copy.textContent = "Copy";
    copy.setAttribute("aria-label", "Copy setup key");

    const status = document.createElement("span");
    status.className = "visually-hidden";
    status.setAttribute("role", "status");
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(secret);
        copy.textContent = "Copied";
        status.textContent = "Setup key copied";
        setTimeout(() => {
          copy.textContent = "Copy";
        }, 2000);
      } catch {
        input.focus();
        input.select();
        status.textContent = "Setup key selected for copying";
      }
    });
    field.append(input, copy);

    const settings = document.createElement("dl");
    settings.className = "row small mt-3 mb-0";

    for (const [name, value] of [
      ["Algorithm", uri.searchParams.get("algorithm")],
      ["Time step", `${uri.searchParams.get("period")} seconds`],
      ["Digits", uri.searchParams.get("digits")],
    ]) {
      const term = document.createElement("dt");
      term.className = "col-4";
      term.textContent = name;

      const valueElement = document.createElement("dd");
      valueElement.className = "col-8";
      valueElement.textContent = value;
      settings.append(term, valueElement);
    }

    manual.append(summary, label, field, status, settings);
    info.replaceChildren(qrField, app, manual);
  }

  function saveCredentialChange() {
    if (!document.getElementById("navbarCollapse"))
      return;

    const form = document.getElementById("credentialUpdateStatusForm");
    const save = form?.querySelector('[hx-post="/ui/api/cu_commit"]');

    if (
      form?.dataset.dirty !== "true" || !save || save.disabled ||
      form.dataset.identitySaving || form.querySelector(".alert-warning, .alert-danger")
    )
      return;

    form.dataset.identitySaving = "true";
    save.setAttribute("hx-disabled-elt", "this");
    save.click();
  }

  function simplifyProfile() {
    const profile = document.querySelector(
      'form#user_settings_container[hx-post="/ui/api/user_settings/edit_profile"], div#user_settings_container.identity-profile',
    );

    if (!profile)
      return;

    const username = profile.querySelector('label[for="personname"]');
    const name = profile.querySelector('label[for="persondisplayname"]');

    if (username)
      username.textContent = "Username";

    if (name)
      name.textContent = "Name";

    for (const button of profile.querySelectorAll('button, a[href="/ui/unlock"], a[hx-get="/ui/api/user_settings/add_email"]')) {
      button.remove();
    }

    profile.querySelector(":scope > .pt-4")?.remove();

    for (const input of profile.querySelectorAll('input[name="name"], input[name="displayname"], input[name="emails[]"]')) {
      input.readOnly = true;
      input.disabled = false;
      input.classList.replace("form-control", "form-control-plaintext");
      input.classList.add("py-0");
    }

    for (const radio of profile.querySelectorAll('input[name="primary_email_index"]')) {
      radio.disabled = true;
      radio.closest(".input-group-text").hidden = true;
    }

    profile.querySelector('label[for="profileEmail"]').textContent = "Email addresses";

    if (!profile.querySelector(".identity-profile-help")) {
      const help = document.createElement("p");
      help.className = "identity-profile-help text-body-secondary mt-4";
      help.textContent = "Contact infrastructure administration to change these details";
      profile.append(help);
    }

    if (profile.tagName !== "FORM")
      return;

    const details = document.createElement("div");
    details.id = profile.id;
    details.className = "identity-profile";
    details.append(...profile.childNodes);
    profile.replaceWith(details);
  }

  function updateAccountNavigation() {
    const navbar = document.querySelector("nav.identity-account-navbar");

    if (!navbar)
      return;

    const profilePaths = ["/ui/profile", "/ui/update_credentials", "/ui/enrol", "/ui/radius", "/ui/reset"];
    const adminPage = location.pathname === "/ui/admin" || location.pathname.startsWith("/ui/admin/");

    for (const link of navbar.querySelectorAll("[data-identity-navigation]")) {
      const url = new URL(link.href, location.href);
      const adminLink = url.pathname === "/ui/admin" || url.pathname.startsWith("/ui/admin/");
      const active = url.origin === location.origin && (
        url.pathname === "/ui/profile"
          ? profilePaths.some((path) => location.pathname === path || location.pathname.startsWith(path + "/"))
          : url.pathname === location.pathname || (adminLink && adminPage)
      );
      link.classList.toggle("active", active);

      if (active)
        link.setAttribute("aria-current", "page");
      else
        link.removeAttribute("aria-current");
    }

    const menu = navbar.querySelector(".identity-account-menu");
    menu?.querySelector("button")?.classList.toggle(
      "active", !!menu.querySelector('.dropdown-menu [aria-current="page"]'),
    );

    const modal = document.getElementById("signoutModal");

    if (modal && !modal.dataset.identityAccountFocus) {
      modal.dataset.identityAccountFocus = "true";
      modal.addEventListener("hidden.bs.modal", () => {
        document.getElementById("identity-account-menu-toggle")?.focus();
      });
    }
  }

  function isPrivateApplication(href) {
    try {
      const url = new URL(href);
      const hostname = url.hostname.toLowerCase().replace(/\.$/, "");

      return url.protocol === "https:" && (
        hostname === privateDomain || hostname.endsWith("." + privateDomain)
      );
    } catch {
      return false;
    }
  }

  function showApplicationAccess() {
    for (const card of document.querySelectorAll("main.container-lg > .row > .col-md-3 > .card")) {
      const link = card.querySelector(":scope > a[href]");
      const icon = link?.querySelector("img.oauth2-img[id]");
      const needsVpn = link && icon && isPrivateApplication(link.href);
      let badge = card.querySelector(":scope > .identity-app-access");

      if (!needsVpn && !badge)
        continue;

      const descriptions = new Set((link?.getAttribute("aria-describedby") || "").split(/\s+/).filter(Boolean));

      if (badge)
        descriptions.delete(badge.id);

      if (needsVpn) {
        if (!badge) {
          badge = document.createElement("span");
          badge.className = "badge rounded-pill identity-app-access";
          badge.id = "identity-app-access-" + icon.id;
          badge.textContent = "VPN only";
          card.append(badge);
        }

        descriptions.add(badge.id);
      } else
        badge.remove();

      if (descriptions.size)
        link?.setAttribute("aria-describedby", [...descriptions].join(" "));
      else
        link?.removeAttribute("aria-describedby");
    }
  }

  let registrationRequest;

  async function showRegistrationGuidance(force = false) {
    const main = document.querySelector("main.container-lg");

    if (
      main?.querySelector(":scope > div > h2")?.textContent.trim() !== "Applications" ||
      main.querySelector(":scope > .row > .col-md-3") ||
      (main.dataset.identityRegistrationChecked && !force) ||
      registrationRequest?.main === main
    )
      return;

    const empty = [...main.querySelectorAll(":scope > p")].find(
      (paragraph) => paragraph.textContent.trim() === "No linked applications available",
    );
    const row = main.querySelector(":scope > .row");
    const guidance = main.querySelector("[data-identity-registration-guidance]");
    const placeholder = empty || (row && !row.querySelector(":scope > .col-md-3") ? row : null) || guidance;

    if (!placeholder)
      return;

    registrationRequest?.controller.abort();

    const controller = new AbortController();
    const request = { main, controller };
    registrationRequest = request;

    const timeout = setTimeout(() => controller.abort(), 5000);

    try {
      const response = await fetch("/v1/self", {
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal,
      });

      if (!response.ok)
        return;

      const memberships = (await response.json())?.youare?.attrs?.memberof;

      if (
        !main.isConnected || registrationRequest !== request || controller.signal.aborted ||
        !Array.isArray(memberships) || memberships.some((value) => typeof value !== "string")
      )
        return;

      main.dataset.identityRegistrationChecked = "true";

      if (memberships.some((value) => value.startsWith("members@"))) {
        if (guidance) {
          const message = document.createElement("p");
          message.textContent = "No linked applications available";
          guidance.replaceWith(message);
        }

        return;
      }

      if (guidance)
        return;

      const registration = document.createElement("div");
      registration.dataset.identityRegistrationGuidance = "";

      const notice = document.createElement("template");
      notice.innerHTML = __IDENTITY_REGISTRATION_NOTICE__;
      registration.append(notice.content.cloneNode(true));
      placeholder.replaceWith(registration);
    } catch {
    } finally {
      clearTimeout(timeout);

      if (registrationRequest === request)
        registrationRequest = null;
    }
  }

  function simplifyAccountNavigation() {
    const sidebar = document.querySelector("main .side-menu");
    sidebar?.querySelector('a[href="/ui/radius"]')?.parentElement.remove();

    const enroll = sidebar?.querySelector('a[href="/ui/enrol"]');

    if (enroll)
      enroll.textContent = "Add another device";
  }

  function initialize() {
    if (
      document.body.classList.contains("identity-auth") &&
      !document.querySelector(
        'main.form-signin, main.shell > .masthead, main.shell:has(form[action="/ui/oauth2/consent"])',
      )
    ) {
      document.body.classList.remove("identity-auth");
      document.body.classList.add("flex-column", "d-flex", "h-100");
    }

    simplifyLogin();
    showConsentProfile();
    simplifyTotpSetup();
    simplifyProfile();
    simplifyAccountNavigation();
    updateAccountNavigation();
    showApplicationAccess();
    showRegistrationGuidance();
    shortenIdentityDisplays();
  }

  if (document.readyState === "complete")
    initialize();
  else
    document.addEventListener("DOMContentLoaded", initialize, { once: true });

  document.body.addEventListener("htmx:afterSwap", initialize);
  document.body.addEventListener("htmx:afterSettle", () => {
    applyAuthLayout();
    simplifyTotpSetup();
    simplifyProfile();
    saveCredentialChange();
    shortenIdentityDisplays();
  });
  document.body.addEventListener("htmx:beforeOnLoad", (event) => {
    const xhr = event.detail.xhr;

    if (
      xhr.status >= 200 && xhr.status < 300 && xhr.responseURL &&
      new URL(xhr.responseURL).pathname === "/ui/api/cu_commit" &&
      xhr.getResponseHeader("HX-Location") === "/ui/login"
    )
      credentialsSaved = true;
  });
  document.body.addEventListener("htmx:beforeSwap", (event) => {
    const section = event.detail.requestConfig?.target?.closest("#credentialUpdateDynamicSection") ||
      event.detail.target?.closest("#credentialUpdateDynamicSection");

    if (!section || !event.detail.xhr.responseURL)
      return;

    const path = new URL(event.detail.xhr.responseURL).pathname;

    if (!["/ui", "/ui/", "/ui/login", "/ui/apps"].includes(path))
      return;

    event.preventDefault();
    event.detail.shouldSwap = false;

    const message = document.createElement("p");
    message.className = "text-danger";
    message.setAttribute("role", "alert");
    message.textContent = "Your credential session expired. Your changes were not saved";

    const retry = document.createElement("a");
    retry.className = "btn btn-primary";
    retry.href = document.getElementById("navbarCollapse")
      ? "/ui/update_credentials" : "/ui/reset";
    retry.textContent = "Try again";
    section.replaceChildren(message, retry);
  });
  document.body.addEventListener("htmx:configRequest", (event) => {
    if (
      event.detail.path === "/ui/login/begin" &&
      typeof event.detail.parameters.username === "string"
    ) {
      event.detail.parameters.username = loginName(
        event.detail.parameters.username,
      );
    }
  });
  window.addEventListener("pageshow", (event) => {
    shortenIdentityDisplays();

    if (event.persisted && document.querySelector("form#login"))
      location.replace("/ui/login");
    else if (event.persisted) {
      updateAccountNavigation();
      showRegistrationGuidance(true);
    }
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      updateAccountNavigation();
      showRegistrationGuidance(true);
    }
  });
})();
