// Browser UI for the decoder. All cryptography lives in crypto.mjs.
import { tryDecryptAll, normalizeKey } from "./crypto.mjs";
import { BLOBS } from "./blobs.js";

const $ = (id) => document.getElementById(id);
const keyEl = $("key"), passEl = $("passphrase"), out = $("result"), go = $("go");

// remember the key for this browser session (best effort; storage may be unavailable)
const STORE = "exfeel-key";
try { const k = sessionStorage.getItem(STORE); if (k) keyEl.value = k; } catch {}
keyEl.addEventListener("change", () => { try { sessionStorage.setItem(STORE, keyEl.value); } catch {} });

// quarter-turn control for the message illustration; the reference panel never turns
let turns = 0;
const labels = ["upright", "a quarter turn", "half a turn", "three quarters"];
$("turn").addEventListener("click", () => {
  turns = (turns + 1) % 4;
  $("message").style.setProperty("--turn", `${turns * 90}deg`);
  $("turn-label").textContent = labels[turns];
});

function show(text, isError) {
  out.textContent = text;
  out.classList.toggle("error", !!isError);
}

$("decoder").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (!globalThis.crypto?.subtle) { show("this page needs a secure (https) connection to decrypt.", true); return; }
  const k = normalizeKey(keyEl.value);
  if (!k.ok) { show(k.error, true); return; }
  try { sessionStorage.setItem(STORE, keyEl.value); } catch {}
  go.disabled = true; out.classList.add("working"); show("working…");
  try {
    const r = await tryDecryptAll(passEl.value, keyEl.value, BLOBS);
    if (r.ok) show(r.plaintext, false); else show(r.error, true);
  } catch (e) {
    show("something went wrong.", true);
  } finally {
    go.disabled = false; out.classList.remove("working");
  }
});
