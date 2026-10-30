(() => {
  document.getElementById("signoutModal")?.addEventListener("hidden.bs.modal", () => {
    document.getElementById("identity-account-menu-toggle")?.focus();
  });

  const authLogin = document.body.dataset.authLogin;
  const localDateTime = new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  });
  const shortTimeZone = new Intl.DateTimeFormat(undefined, {
    timeZoneName: "short",
  });
  const fullLocalDateTime = new Intl.DateTimeFormat(undefined, {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "long",
  });

  function localizeTimes(root = document) {
    for (const element of root.querySelectorAll("time[datetime]")) {
      const instant = new Date(element.dateTime);

      if (Number.isNaN(instant.getTime()))
        continue;

      element.textContent = localDateTime.format(instant);
      element.title = fullLocalDateTime.format(instant);
    }
  }

  function localInputValue(instant) {
    const pad = (value, width = 2) => String(value).padStart(width, "0");

    const day = [
      pad(instant.getFullYear(), 4),
      pad(instant.getMonth() + 1),
      pad(instant.getDate()),
    ].join("-");
    const clock = `${pad(instant.getHours())}:${pad(instant.getMinutes())}`;

    return `${day}T${clock}`;
  }

  function expiryInstant(input) {
    const instant = new Date(
      input.value === input.dataset.initialLocalValue
        ? input.dataset.initialInstant || input.value
        : input.value,
    );

    if (
      Number.isNaN(instant.getTime()) ||
      localInputValue(instant).slice(0, 16) !== input.value.slice(0, 16)
    )
      return null;

    return instant;
  }

  function updateExpiryContext(form, input) {
    const instant = expiryInstant(input);
    const zone = form.querySelector("[data-expiry-zone]");

    if (zone) {
      zone.textContent = instant
        ? shortTimeZone
            .formatToParts(instant)
            .find((part) => part.type === "timeZoneName").value
        : "";
    }

    input.title = instant ? fullLocalDateTime.format(instant) : "";
  }

  function initializeMemberFields(root) {
    for (const form of root.querySelectorAll(".group-membership-form")) {
      const input = form.querySelector("[data-member-search]");

      if (!input)
        continue;

      const list = form.querySelector("[data-member-options]");
      const status = form.querySelector("[data-member-search-status]");
      const expiry = form.querySelector('input[name="expires_at"]');
      const utc = form.querySelector('input[name="expires_at_utc"]');
      const editing = form.querySelector('input[name="editing_username"]');
      const heading = form.querySelector("[data-member-form-heading]");
      const submit = form.querySelector("[data-member-submit]");
      const modalElement = form.closest("[data-member-modal]");
      const modal = window.bootstrap.Modal.getOrCreateInstance(modalElement);
      const add = root.querySelector("[data-add-member]");
      const errors = form.querySelector("[data-member-errors]");
      let returnFocus = add;
      const existing = new Set(JSON.parse(form.dataset.existingMembers || "[]"));
      const editable = new Map(
        [...root.querySelectorAll("[data-edit-member]")].map((button) => [
          button.dataset.memberUsername,
          button,
        ]),
      );
      let options = [];
      let active = -1;
      let resultQuery = "";
      let selectedUsername = form.dataset.editing === "true" ? input.value : "";
      let sequence = 0;
      let timer;
      let controller;

      function close() {
        list.hidden = true;
        input.setAttribute("aria-expanded", "false");
        input.removeAttribute("aria-activedescendant");

        for (const option of list.children)
          option.setAttribute("aria-selected", "false");

        active = -1;
      }

      function cancelLookup() {
        clearTimeout(timer);
        controller?.abort();
        sequence++;
        status.textContent = "";
      }

      function setExpiry(iso) {
        const instant = new Date(iso);

        if (Number.isNaN(instant.getTime()))
          return;

        expiry.value = localInputValue(instant);
        expiry.dataset.initialInstant = iso;
        expiry.dataset.initialLocalValue = expiry.value;
        expiry.setCustomValidity("");
        utc.value = "";
        updateExpiryContext(form, expiry);
      }

      function editMember(username, preserveExpiry = false) {
        const button = editable.get(username);
        cancelLookup();
        close();

        if (!button) {
          input.setCustomValidity("This member cannot be edited here");
          status.textContent = "This member cannot be edited here";

          return false;
        }

        input.value = username;
        input.readOnly = true;
        input.setCustomValidity("");
        selectedUsername = username;
        editing.value = username;
        form.dataset.editing = "true";

        if (heading)
          heading.textContent = "Edit expiry";

        submit.textContent = "Save expiry";
        status.textContent = "";

        if (!preserveExpiry)
          setExpiry(button.dataset.memberExpiry);

        return true;
      }

      function choose(index) {
        const member = options[index];

        if (!member)
          return;

        input.value = member.username;
        input.setCustomValidity("");
        selectedUsername = member.username;
        cancelLookup();
        close();
        status.textContent = "";

        if (existing.has(member.username) && editMember(member.username))
          expiry.focus();
        else
          input.focus();
      }

      function activate(index) {
        active = index;
        list.hidden = false;
        input.setAttribute("aria-expanded", "true");

        for (const [position, option] of [...list.children].entries()) {
          option.setAttribute("aria-selected", String(position === active));
        }

        const option = list.children[active];
        input.setAttribute("aria-activedescendant", option.id);
        option.scrollIntoView({ block: "nearest" });
      }

      function render(members, query) {
        options = members;
        resultQuery = query;

        const elements = members.map((member, index) => {
          const option = document.createElement("li");
          option.id = `${list.id}-${index}`;
          option.setAttribute("role", "option");
          option.setAttribute("aria-selected", "false");
          option.dataset.index = index;

          const username = document.createElement("span");
          username.className = "member-option-username";
          username.textContent = member.username;
          option.append(username);

          if (member.display_name !== member.username) {
            const name = document.createElement("span");
            name.className = "member-option-name";
            name.textContent = member.display_name;
            option.append(name);
          }

          return option;
        });
        list.replaceChildren(...elements);
        close();

        if (members.length) {
          list.hidden = false;
          input.setAttribute("aria-expanded", "true");
        }

        status.textContent = members.length
          ? `${members.length} matching ${members.length === 1 ? "member" : "members"}`
          : "No matching members";
      }

      function search() {
        if (input.readOnly)
          return;

        cancelLookup();
        close();
        options = [];
        selectedUsername = "";
        input.setCustomValidity("");
        status.textContent = "";

        const query = input.value.trim();

        if (query.length < 2)
          return;

        const version = sequence;
        timer = setTimeout(async () => {
          controller = new AbortController();
          status.textContent = "Searching…";

          const current = () => version === sequence &&
            input.value.trim() === query && document.activeElement === input;

          try {
            const parameters = new URLSearchParams({ group: form.dataset.groupId, q: query });
            const response = await fetch(`/access/members?${parameters}`, {
              credentials: "same-origin",
              headers: { Accept: "application/json" },
              signal: controller.signal,
            });

            if (!current())
              return;

            if (!response.ok)
              throw new Error("Member search unavailable");

            const result = await response.json();

            if (!current())
              return;

            if (!Array.isArray(result.members) || result.members.length > 10 ||
              result.members.some((member) =>
                !member || !/^[a-z][a-z0-9_-]{2,31}$/.test(member.username) ||
                typeof member.display_name !== "string")) {
              throw new Error("Invalid member search response");
            }

            render(result.members, query);
          } catch (error) {
            if (current() && error.name !== "AbortError") {
              status.textContent = "Member search unavailable";
            }
          }
        }, 250);
      }

      input.addEventListener("input", (event) => {
        if (!event.isComposing)
          search();
      });
      input.addEventListener("compositionend", search);
      input.addEventListener("focus", () => {
        if (input.readOnly || input.value === selectedUsername)
          return;

        if (options.length && resultQuery === input.value.trim()) {
          list.hidden = false;
          input.setAttribute("aria-expanded", "true");
        } else
          search();
      });
      input.addEventListener("keydown", (event) => {
        if (event.isComposing || input.readOnly)
          return;

        if (event.key === "Escape") {
          event.preventDefault();

          if (!list.hidden)
            event.stopPropagation();

          cancelLookup();
          close();
          status.textContent = "";
        } else if (event.key === "Enter" && !list.hidden) {
          event.preventDefault();

          if (active >= 0)
            choose(active);
        } else if ((event.key === "ArrowDown" || event.key === "ArrowUp") &&
          options.length && resultQuery === input.value.trim()) {
          event.preventDefault();

          const next = event.key === "ArrowDown"
            ? (active + 1) % options.length
            : (active < 0 ? options.length - 1 : (active - 1 + options.length) % options.length);
          activate(next);
        } else if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
          input.removeAttribute("aria-activedescendant");

          for (const option of list.children)
            option.setAttribute("aria-selected", "false");

          active = -1;
        }
      });
      input.addEventListener("blur", () => {
        setTimeout(() => {
          if (document.activeElement === input)
            return;

          cancelLookup();
          close();

          if (!input.readOnly && existing.has(input.value.trim())) {
            editMember(input.value.trim());
          }
        }, 0);
      });
      list.addEventListener("mousedown", (event) => event.preventDefault());
      list.addEventListener("click", (event) => {
        const option = event.target.closest('[role="option"]');

        if (option && list.contains(option))
          choose(Number(option.dataset.index));
      });

      for (const [username, button] of editable) {
        button.addEventListener("click", () => {
          resetMember();

          if (editMember(username)) {
            returnFocus = button;
            modal.show();
          }
        });
      }

      function resetMember() {
        cancelLookup();
        close();
        form.dataset.editing = "false";
        editing.value = "";
        input.value = "";
        input.readOnly = false;
        input.setCustomValidity("");
        selectedUsername = "";
        submit.textContent = "Add member";

        if (heading)
          heading.textContent = "Add member";

        if (errors)
          errors.hidden = true;

        status.textContent = "";
        setExpiry(form.dataset.addDefaultInstant || expiry.dataset.defaultInstant);
      }

      add.addEventListener("click", () => {
        resetMember();
        returnFocus = add;
        modal.show();
      });
      modalElement.addEventListener("shown.bs.modal", () => {
        if (errors && !errors.hidden)
          errors.focus();
        else
          (input.readOnly ? expiry : input).focus();
      });
      modalElement.addEventListener("hide.bs.modal", () => {
        cancelLookup();
        close();
      });
      modalElement.addEventListener("hidden.bs.modal", () => {
        returnFocus.focus();
      });
      form.addEventListener("submit", (event) => {
        const username = input.value.trim();

        if (existing.has(username) && editing.value !== username) {
          event.preventDefault();

          if (editMember(username))
            expiry.focus();
          else
            input.reportValidity();
        }
      });

      if (form.dataset.editing === "true")
        editMember(input.value, true);

      if (form.dataset.memberReopen === "true") {
        returnFocus = form.dataset.editing === "true" ? editable.get(input.value) || add : add;
        modal.show();
      }
    }
  }

  function initializeRegistrationFields(root) {
    for (const picker of root.querySelectorAll("[data-study-picker]")) {
      const search = picker.querySelector("[data-study-search]");
      const native = picker.querySelector("[data-study-native]");
      const popup = picker.querySelector("[data-study-dropdown]");
      const list = picker.querySelector("[data-study-results]");
      const selectedList = picker.querySelector("[data-study-selected]");
      const status = picker.querySelector("[data-study-status]");
      const school = picker.closest("form").querySelector("[data-school-level]");
      const required = picker.querySelector("[data-study-required]");
      const empty = picker.querySelector("[data-study-empty]");

      const normalize = (value) => value.normalize("NFKD")
        .replace(/\p{M}/gu, "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();

      const entries = [...native.querySelectorAll("[data-study-option]")].map((label) => {
        const name = label.querySelector("[data-study-name]").textContent.trim();
        const checkbox = label.querySelector("input");

        return {name, checkbox, text: normalize(name)};
      });
      let results = [];
      let active = -1;

      function score(text, query) {
        if (!query)
          return 0;

        if (text === query)
          return 0;

        if (text.startsWith(query))
          return 1 + text.length / 1000;

        const words = text.split(" ");
        const initials = words.filter((word) => !["and", "of", "or", "the"].includes(word))
          .map((word) => word[0]).join("");
        const compactQuery = query.replaceAll(" ", "");

        if (initials.startsWith(compactQuery))
          return 2 + text.length / 1000;

        let rank = text.length / 1000;

        for (const token of query.split(" ")) {
          if (words.some((word) => word.startsWith(token))) {
            rank += 3;
            continue;
          }

          if (token.length < 3)
            return Infinity;

          if (text.includes(token)) {
            rank += 4;
            continue;
          }

          let position = 0;
          let gaps = 0;

          for (const character of token) {
            const next = text.indexOf(character, position);

            if (next < 0)
              return Infinity;

            gaps += next - position;
            position = next + 1;
          }

          if (gaps > token.length * 2)
            return Infinity;

          rank += 5 + gaps;
        }

        return rank;
      }

      function close() {
        popup.hidden = true;
        search.setAttribute("aria-expanded", "false");
        search.removeAttribute("aria-activedescendant");
        active = -1;
      }

      function highlight(index) {
        active = index;

        for (const [position, option] of [...list.children].entries()) {
          option.setAttribute("aria-selected", String(position === active));
        }

        const option = list.children[active];

        if (option) {
          search.setAttribute("aria-activedescendant", option.id);

          const viewport = list.getBoundingClientRect();
          const bounds = option.getBoundingClientRect();

          if (bounds.top < viewport.top)
            list.scrollTop += bounds.top - viewport.top;
          else if (bounds.bottom > viewport.bottom)
            list.scrollTop += bounds.bottom - viewport.bottom;
        } else
          search.removeAttribute("aria-activedescendant");
      }

      function showResults() {
        const query = normalize(search.value);
        results = entries.filter((entry) => !entry.checkbox.checked)
          .map((entry) => ({entry, rank: score(entry.text, query)}))
          .filter((item) => Number.isFinite(item.rank))
          .sort((a, b) => a.rank - b.rank);
        list.replaceChildren();

        for (const [index, {entry}] of results.entries()) {
          const option = document.createElement("li");
          option.id = `registration-study-result-${entry.checkbox.value}`;
          option.setAttribute("role", "option");
          option.textContent = entry.name;
          option.addEventListener("pointerdown", (event) => event.preventDefault());
          option.addEventListener("pointermove", () => highlight(index));
          option.addEventListener("click", () => choose(entry));
          list.append(option);
        }

        list.hidden = !results.length;
        empty.hidden = results.length > 0;
        popup.hidden = false;
        search.setAttribute("aria-expanded", String(results.length > 0));
        highlight(results.length ? 0 : -1);
      }

      function choose(entry) {
        entry.checkbox.checked = true;
        entry.checkbox.dispatchEvent(new Event("change", {bubbles: true}));
        search.value = "";
        search.focus();
        close();
        status.textContent = `${entry.name} added`;
      }

      function updateSelection() {
        const needed = school.selectedOptions[0]?.hasAttribute("data-student") || false;
        selectedList.replaceChildren();

        for (const entry of entries) {
          if (!entry.checkbox.checked)
            continue;

          const item = document.createElement("li");
          const description = document.createElement("span");
          description.textContent = entry.name;

          const remove = document.createElement("button");
          remove.type = "button";
          remove.className = "study-remove";
          remove.setAttribute("aria-label", `Remove ${entry.name}`);
          remove.textContent = "×";
          remove.addEventListener("click", () => {
            entry.checkbox.checked = false;
            entry.checkbox.dispatchEvent(new Event("change", {bubbles: true}));
            search.focus();
            close();
            status.textContent = `${entry.name} removed`;
          });
          item.append(description, remove);
          selectedList.append(item);
        }

        selectedList.hidden = !selectedList.children.length;
        required.hidden = !needed;

        const hasStudy = entries.some((entry) => entry.checkbox.checked);
        search.setCustomValidity(needed && !hasStudy ? "Select at least one field of study" : "");

        if (!popup.hidden)
          showResults();
      }

      native.hidden = true;
      search.hidden = false;
      search.addEventListener("input", showResults);
      search.addEventListener("focus", showResults);
      search.addEventListener("click", showResults);
      search.addEventListener("keydown", (event) => {
        if (event.isComposing)
          return;

        if (event.key === "ArrowDown" || event.key === "ArrowUp") {
          event.preventDefault();

          if (popup.hidden) {
            showResults();

            if (event.key === "ArrowUp")
              highlight(results.length - 1);
          } else if (results.length) {
            const step = event.key === "ArrowDown" ? 1 : -1;
            highlight(active < 0 ? (step > 0 ? 0 : results.length - 1)
              : (active + step + results.length) % results.length);
          }
        } else if (event.key === "Enter") {
          event.preventDefault();

          if (!popup.hidden && results[active])
            choose(results[active].entry);
        } else if (event.key === "Escape") {
          if (!popup.hidden)
            event.preventDefault();

          close();
        } else if (event.key === "Tab")
          close();
        else if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key))
          highlight(-1);
      });
      picker.addEventListener("focusout", (event) => {
        if (!picker.contains(event.relatedTarget))
          close();
      });
      document.addEventListener("pointerdown", (event) => {
        if (!picker.contains(event.target))
          close();
      });
      school.addEventListener("change", updateSelection);

      for (const entry of entries)
        entry.checkbox.addEventListener("change", updateSelection);

      updateSelection();
    }

    for (const fieldset of root.querySelectorAll("[data-required-choices]")) {
      const choices = [...fieldset.querySelectorAll('input[type="checkbox"]')];

      const update = (event) => {
        const selected = event?.target;

        if (selected?.name === "ethnicity" && selected.checked) {
          for (const choice of choices) {
            if (choice === selected || !choice.checked)
              continue;

            if (selected.value !== "prefer_not_to_say" && choice.value !== "prefer_not_to_say")
              continue;

            choice.checked = false;
            choice.dispatchEvent(new Event("change", { bubbles: true }));
          }
        }

        choices[0].setCustomValidity(
          choices.some((choice) => choice.checked) ? "" : "Select at least one option",
        );
      };

      for (const choice of choices)
        choice.addEventListener("change", update);

      update();
    }
  }

  function localizePage(root = document) {
    localizeTimes(root);

    for (const navigation of root.querySelectorAll("[data-group-navigation]")) {
      const mobile = window.matchMedia("(max-width: 575.98px)");

      const layout = () => {
        navigation.open = !mobile.matches;
      };

      layout();
      mobile.addEventListener("change", layout);
    }

    for (const form of root.querySelectorAll(".group-membership-form")) {
      const input = form.querySelector('input[name="expires_at"]');
      const utc = form.querySelector('input[name="expires_at_utc"]');
      const instant = new Date(input.dataset.defaultInstant);
      const submitted = input.dataset.submittedLocal === "true";

      if (!submitted && Number.isNaN(instant.getTime()))
        continue;

      if (!submitted)
        input.value = localInputValue(instant);

      input.dataset.initialLocalValue = input.value;
      input.dataset.initialInstant = submitted ? utc.value : input.dataset.defaultInstant;
      form.dataset.localExpiry = "true";
      updateExpiryContext(form, input);
      input.addEventListener("input", () => {
        input.setCustomValidity("");
        utc.value = "";
        updateExpiryContext(form, input);
      });
    }

    initializeMemberFields(root);
    initializeRegistrationFields(root);

    for (const companion of root.querySelectorAll("[data-followup-for]")) {
      const form = companion.closest("form");
      const field = companion.dataset.followupFor;
      const value = companion.dataset.followupValue;

      if (!form || !/^[a-z_]+$/.test(field))
        continue;

      const choices = [...form.querySelectorAll(`[name="${field}"]`)];
      const input = companion.querySelector("input");

      const update = () => {
        const selected = choices.some((choice) =>
          choice.tagName === "SELECT"
            ? choice.value === value
            : choice.checked && choice.value === value,
        );
        companion.hidden = !selected;
        input.disabled = !selected;
        input.required = selected;

        const required = companion.querySelector("[data-other-required]");

        if (required)
          required.hidden = !selected;
      };

      for (const choice of choices)
        choice.addEventListener("change", update);

      update();
    }
  }

  localizePage();

  for (const browser of document.querySelectorAll("[data-group-browser]")) {
    const input = browser.querySelector("[data-group-search-input]");
    const items = [...browser.querySelectorAll("[data-group-item]")];
    const count = browser.querySelector("[data-group-count]");
    const membershipCount = count.textContent;
    const empty = browser.querySelector("[data-group-no-results]");
    const sections = [...browser.querySelectorAll("[data-group-section]")];
    const disclosures = [...browser.querySelectorAll("details[data-group-section]")];
    const priorOpen = new Map();
    let searching = false;
    input.addEventListener("input", () => {
      const query = input.value.trim().toLowerCase();

      if (query && !searching) {
        for (const details of disclosures)
          priorOpen.set(details, details.open);
      }

      let matches = 0;

      for (const item of items) {
        item.hidden = !item.dataset.groupSearch.toLowerCase().includes(query);

        if (!item.hidden)
          matches++;
      }

      for (const section of sections) {
        section.hidden = ![...section.querySelectorAll("[data-group-item]")].some(
          (item) => !item.hidden,
        );
      }

      for (const details of disclosures) {
        if (query && !details.hidden)
          details.open = true;
        else if (!query && searching)
          details.open = priorOpen.get(details);
      }

      browser.querySelector("[data-group-empty]")?.toggleAttribute("hidden", !!query);
      count.textContent = query
        ? `${matches} of ${items.length} groups`
        : membershipCount;
      empty.hidden = !query || matches > 0;
      searching = !!query;
    });
  }

  document.addEventListener("submit", async (event) => {
    const form = event.target;

    if (form.matches(".group-membership-form")) {
      if (form.dataset.localExpiry !== "true")
        return;

      const input = form.querySelector('input[name="expires_at"]');
      const instant = expiryInstant(input);

      if (!instant) {
        event.preventDefault();
        form.querySelector('input[name="expires_at_utc"]').value = "";
        input.setCustomValidity("Choose a valid local date and time");
        input.reportValidity();

        return;
      }

      input.setCustomValidity("");
      form.querySelector('input[name="expires_at_utc"]').value =
        input.value === input.dataset.initialLocalValue && input.dataset.initialInstant
          ? input.dataset.initialInstant
          : instant.toISOString();

      return;
    }

    if (!form.matches("[data-credential-flow]"))
      return;

    event.preventDefault();

    if (form.dataset.submitting)
      return;

    form.dataset.submitting = "true";

    const submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;

    try {
      const response = await fetch(form.action, {
        method: "POST",
        body: new FormData(form),
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });

      if (response.headers.get("content-type")?.includes("application/json")) {
        const result = await response.json();

        if (result.redirect !== authLogin && result.redirect !== "/membership")
          throw new Error("Unexpected destination");

        location.assign(result.redirect);

        return;
      }

      if (new URL(response.url).origin !== location.origin) {
        location.assign(authLogin);

        return;
      }

      const html = new DOMParser().parseFromString(
        await response.text(),
        "text/html",
      );
      const content = html.getElementById("content");

      if (!content)
        throw new Error("Missing account page");

      const notice = content.querySelector('[role="alert"]');

      if (response.status !== 400 || !notice) {
        document.getElementById("content").replaceWith(content);
        localizePage(content);

        const pageUrl = new URL(response.url);

        if (["/join/complete", "/setup/finish"].includes(pageUrl.pathname)) {
          pageUrl.pathname = content.querySelector(
            '[data-credential-flow][action="/join/complete"]',
          ) ? "/join/profile" : "/setup";
        }

        history.replaceState(null, "", pageUrl);
        document.title = html.title;
        content.querySelector("[autofocus]")?.focus();

        return;
      }

      const incoming = content.querySelector("[data-credential-flow]");

      if (incoming) {
        form.action = incoming.getAttribute("action");

        if (form.getAttribute("action") === "/setup")
          history.replaceState(null, "", "/setup");

        const compatibility = incoming.querySelector(
          '.check-label:has(input[name="allow_sha1"])',
        );

        if (compatibility && !form.querySelector('input[name="allow_sha1"]'))
          submit.before(compatibility);
      }

      const card = form.closest(".card");
      card.querySelector('[role="alert"]')?.remove();
      card.querySelector("h1").after(notice);
      form.querySelector('input[type="password"], input[name="code"]')?.focus();
    } catch {
      const card = form.closest(".card");
      card.querySelector('[role="alert"]')?.remove();

      const notice = document.createElement("div");
      notice.className = "alert alert-danger";
      notice.setAttribute("role", "alert");
      notice.textContent = "Something went wrong. Try again";
      card.querySelector("h1").after(notice);
    } finally {
      delete form.dataset.submitting;
      submit.disabled = false;
    }
  });
  window.addEventListener("pageshow", (event) => {
    if (event.persisted)
      location.reload();
  });
})();
