(** shellproof_interp — OCaml interpretation / report layer
    Reads the Rust probe layer's JSON report (stdin), applies the typed
    verdict mapping and CVE knowledge base, and emits a schema-conformant
    report (report_schema.json) to stdout.

    Build: dune build
    Run:   shellproof <target> --json | shellproof_interp.exe

    The Rust layer already classifies each probe into a verdict with evidence;
    this layer gives it a disclosure-ready shape (descriptions, fixes,
    probe_type, scan wrapper) and normalises verdicts to the schema enum. *)

module J = Yojson.Safe
module U = Yojson.Safe.Util

(** ── CVE knowledge base ──────────────────────────────────────────────────── *)

let cve_description = function
  | "CVE-2026-111497" ->
      "Brotli decoder OOB write (Node2Shell / HTTP2Shell) — \
       DecodeBlockTypeAndLength() invalid block switch. \
       Fixed: Google Brotli 1.2.1 commit 0ed4268a; Node.js 22.23.4/24.22.1/26.12.1."
  | "CVE-2026-109618" ->
      "PHP OOM corruption — longjmp() leaves request memory in invalid state before init. \
       Fixed: php-src commit 3584a98bda0f (PHP 8.2.35/8.3.36/8.4.27/8.5.12)."
  | "CVE-2026-109619" ->
      "PHP stale global state — worker globals point into freed request memory. \
       Same fix commit as 109618 (3584a98bda0f)."
  | "CVE-2026-115560" ->
      "PHP session upload-progress serializer mismatch — no upstream patch as of Nov 2026. \
       Mitigation: session.upload_progress.enabled=0 in php.ini."
  | other -> Printf.sprintf "Unknown CVE identifier: %s" other

let recommended_fix = function
  | "CVE-2026-111497" ->
      "Update Node.js to 22.23.4 / 24.22.1 / 26.12.1 or the Brotli library to 1.2.1."
  | "CVE-2026-109618" | "CVE-2026-109619" ->
      "Update PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. If < 8.2 (EOL), apply a community \
       backport or migrate. Interim: pm.max_requests=1 to recycle FPM workers aggressively."
  | "CVE-2026-115560" ->
      "Set session.upload_progress.enabled=0 in php.ini (or the FPM pool config). \
       Apply the upstream fix in the next regular PHP release when available."
  | _ -> "No fix mapping available for this identifier."

(* 115560 is a passive feature/version check; the other three are active probes. *)
let probe_type = function
  | "CVE-2026-115560" -> "passive"
  | _ -> "active"

(** Normalise the Rust SCREAMING_SNAKE verdict to the schema enum.
    NOT_APPLICABLE has no schema slot → fold into "inconclusive". *)
let normalise_verdict = function
  | "PATCHED" -> "patched"
  | "VULNERABLE" -> "vulnerable"
  | "INCONCLUSIVE" -> "inconclusive"
  | "NOT_APPLICABLE" -> "inconclusive"
  | "ERROR" -> "error"
  | other -> String.lowercase_ascii other

(** ── JSON helpers ────────────────────────────────────────────────────────── *)

let str_opt j = try U.to_string_option j with _ -> None
let str_def d j = match str_opt j with Some s -> s | None -> d

(* Greatest elapsed/after milliseconds seen across a signals array. *)
let signals_duration_ms (signals : J.t) : int =
  let one acc sig_ =
    match sig_ with
    | `Assoc kvs ->
        List.fold_left
          (fun a (_k, v) ->
            match v with
            | `Assoc inner ->
                let pick name a =
                  match List.assoc_opt name inner with
                  | Some (`Int n) -> max a n
                  | _ -> a
                in
                a |> pick "elapsed_ms" |> pick "after_ms"
            | _ -> a)
          acc kvs
    | _ -> acc
  in
  match signals with `List l -> List.fold_left one 0 l | _ -> 0

(* The Rust result carries either an "evidence" object (patched/vulnerable) with
   its own "signals", or a top-level "signals" (inconclusive). Find whichever. *)
let result_signals (r : J.t) : J.t =
  match U.member "evidence" r with
  | `Assoc _ as ev -> U.member "signals" ev
  | _ -> U.member "signals" r

let evidence_summary (r : J.t) : string option =
  match U.member "evidence" r with
  | `Assoc _ as ev -> str_opt (U.member "signal_summary" ev)
  | _ -> None

(* Pull the dominant raw signal kind out of the evidence signals, if any
   (externally-tagged enum: the key of the first signal object). *)
let dominant_signal_kind (r : J.t) : string option =
  match result_signals r with
  | `List (first :: _) -> (
      match first with `Assoc ((k, _) :: _) -> Some k | _ -> None)
  | _ -> None

(** ── scan id (no extra deps) ─────────────────────────────────────────────── *)

let () = Random.self_init ()

let scan_id () =
  (* Random.bits () yields 30 random bits — no bound-argument pitfalls. *)
  let b () = Random.bits () in
  Printf.sprintf "%08x-%04x-%04x-%08x"
    (b () land 0xffffffff) (b () land 0xffff) (b () land 0xffff) (b () land 0xffffffff)

(** ── per-result → schema object ──────────────────────────────────────────── *)

let interpret_result (r : J.t) : J.t =
  let cve = str_def "UNKNOWN" (U.member "cve" r) in
  let raw_verdict = str_def "ERROR" (U.member "verdict" r) in
  let verdict = normalise_verdict raw_verdict in
  let duration_ms = signals_duration_ms (result_signals r) in
  let base =
    [ ("cve", `String cve);
      ("verdict", `String verdict);
      ("probe_type", `String (probe_type cve));
      ("duration_ms", `Int duration_ms);
      ("description", `String (cve_description cve));
      ("recommended_fix", `String (recommended_fix cve)) ]
  in
  let extra =
    match raw_verdict with
    | "VULNERABLE" ->
        let sk = match dominant_signal_kind r with Some k -> k | None -> "observed_crash_signal" in
        let ev =
          match evidence_summary r with
          | Some s -> s
          | None -> "behavioral patch-diff: target matched the pre-patch (broken) path"
        in
        [ ("signal_kind", `String sk); ("evidence", `String ev) ]
    | "INCONCLUSIVE" ->
        [ ("reason", `String (str_def "ambiguous signals" (U.member "reason" r))) ]
    | "NOT_APPLICABLE" ->
        [ ("reason", `String ("N/A: " ^ str_def "probe not applicable to this target" (U.member "reason" r))) ]
    | "ERROR" ->
        [ ("reason", `String (str_def "probe error" (U.member "error" r))) ]
    | _ -> []
  in
  `Assoc (base @ extra)

(** ── entry point ─────────────────────────────────────────────────────────── *)

let () =
  let raw = In_channel.input_all stdin in
  let root =
    try J.from_string raw
    with _ ->
      prerr_endline "shellproof_interp: input is not valid JSON";
      exit 2
  in
  let results_json =
    match U.member "results" root with
    | `List _ as l -> l
    | _ -> ( match root with `List _ as l -> l | _ -> `List [] )
  in
  let results =
    match results_json with `List l -> List.map interpret_result l | _ -> []
  in
  let target = str_def "unknown" (U.member "target" root) in
  let timestamp =
    match str_opt (U.member "scanned_at" root) with Some s -> s | None -> ""
  in
  let tool_version =
    match U.member "tool" root with
    | `Assoc _ as t -> str_def "0.1.0" (U.member "version" t)
    | _ -> "0.1.0"
  in
  (* roll-up counts for a quick human line on stderr *)
  let count v =
    List.length
      (List.filter
         (fun r -> match r with `Assoc kvs -> List.assoc_opt "verdict" kvs = Some (`String v) | _ -> false)
         results)
  in
  Printf.eprintf
    "shellproof_interp: %d result(s) — vulnerable=%d patched=%d inconclusive=%d error=%d\n%!"
    (List.length results) (count "vulnerable") (count "patched")
    (count "inconclusive") (count "error");
  let report =
    `Assoc
      [ ("scan_id", `String (scan_id ()));
        ("target", `String target);
        ("timestamp", `String timestamp);
        ("tool_version", `String tool_version);
        ("results", `List results) ]
  in
  print_string (J.pretty_to_string report);
  print_newline ()
