import { JSDOM, VirtualConsole } from "jsdom";

const MAX_EXECUTION_TIME = 1500;

(async () => {
  try {

    /* ===============================
       READ STDIN PAYLOAD
    =============================== */

    let input = "";

    for await (const chunk of process.stdin) {
      input += chunk;
    }

    if (!input.trim()) {
      console.log(JSON.stringify({ error: "Empty payload" }));
      process.exit(0);
    }

    const { base_html = "", user_code = "", validation = {} } =
      JSON.parse(input);

    /* ===============================
       BUILD DOM
    =============================== */

    const virtualConsole = new VirtualConsole();

    const dom = new JSDOM(`
      <!DOCTYPE html>
      <html>
        <body>
          ${base_html}
          <script>
            try {
              ${user_code}
            } catch(e){}
          </script>
        </body>
      </html>
    `, {
      runScripts: "dangerously",
      virtualConsole
    });

    await new Promise(resolve =>
      setTimeout(resolve, MAX_EXECUTION_TIME)
    );

    const document = dom.window.document;

    /* ===============================
       VALIDATION ENGINE
    =============================== */

    const results = {};
    let passedAll = true;

    const objectives = validation.objectives || [];

    for (const obj of objectives) {
      let passed = false;

      switch (obj.type) {

        /* ===============================
           LESSON 1 — CODE CHECK
        =============================== */
        case "code_contains":
          passed = user_code.includes(obj.value);
          break;

        /* ===============================
           ELEMENT EXISTS
        =============================== */
        case "exists":
          passed = !!document.querySelector(obj.selector);
          break;

        /* ===============================
           LESSON 2 — TEXT CHANGE
        =============================== */
        case "textContent": {
          const el = document.querySelector(obj.selector);
          passed =
            el?.textContent?.trim() === obj.expected?.trim();
          break;
        }

        /* ===============================
           LESSON 3 — CLASS ADDED
        =============================== */
        case "classContains": {
          const el = document.querySelector(obj.selector);
          passed =
            el?.classList.contains(obj.className);
          break;
        }

        /* ===============================
           LESSON 4 — COUNT ELEMENTS
        =============================== */
        case "count":
          passed =
            document.querySelectorAll(obj.selector).length === obj.expected;
          break;

        default:
          passed = false;
      }

      results[obj.id] = {
        label: obj.label,
        passed
      };

      if (!passed) passedAll = false;
    }

    /* ===============================
       RETURN RESULT
    =============================== */

    console.log(JSON.stringify({
      objectives: results,
      passed: passedAll
    }));

    process.exit(0);

  } catch (err) {
    console.log(JSON.stringify({
      error: err.message
    }));
    process.exit(0);
  }
})();