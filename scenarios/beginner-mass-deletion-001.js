/* CTI Casefile — Scenario definition
 * Pure data. Loaded as a classic script so the app also works from file://
 * (fetch() of JSON would be blocked by CORS on a local disk).
 *
 * Source of truth for content: ../new.scenario (beginner-mass-deletion-001)
 *
 * Note on answer order: the engine re-orders every question from the case seed
 * (see shuffleCase in app.js), so the order below is only the authoring order.
 * It is deliberately varied anyway — no single-answer question puts the correct
 * option first, and no multi-select question puts the correct options in the
 * leading slots — so the source is safe to read even without the shuffle.
 *
 * One record here is not a Windows event id: the deletion burst comes from the
 * file server's own audit trail (FILE), which is why it would never appear in the
 * Security log an analyst usually starts from.
 */
(function () {
  window.CTI_SCENARIOS = window.CTI_SCENARIOS || [];

  window.CTI_SCENARIOS.push({
    id: 'beginner-mass-deletion-001',
    title: 'The Empty Folder',
    difficulty: 'Beginner',
    seed: 111,
    caseRef: 'CASE 008',
    host: 'sec-win-03',
    host_ip: '10.0.4.11',
    log_sources: ['auth', 'network'],

    mission: {
      brief: 'Investigate workstation sec-win-03 and a missing folder on the file server.',
      objective: 'Establish what happened to the shared folder, and whether rneuman meant to do it.',
      client: 'Internal Security Operations — Tier 1 Escalation Desk'
    },

    narrative:
      'An internal user deleted 50 files from a shared network folder in under five minutes. Whether ' +
      'accidental, malicious, or an early stage of impact, mass deletion on a shared resource is a ' +
      'high-priority investigation. The user disconnected shortly after, and no backup notice was filed.',

    /* ---------------------------------------------------------------
     * Strings the engine reads from the scenario, so no fact about this
     * case is written into app.js. Every value here comes from new.scenario;
     * the evidence, stream and questions that follow are built on it.
     * --------------------------------------------------------------- */
    engine: {
      /* stage 2 — the record stream banner */
      stream: {
        window: '08:00–08:45',
        files: ['secwin3-events.evtx', 'fileserver-audit.log', 'proxy-flows.log']
      },

      /* stage 5 / 6 — section headings and the progress checklist labels */
      sections: {
        behaviour: 'name the behaviour',
        second: 'read the deletion record',
        trail: 'assemble the sequence',
        attack: 'map it to attack',
        attackAlso: 'supporting techniques',
        iocs: 'keep the intelligence'
      },

      /* stage 1 — the three questions the analyst carries into the data */
      carryQuestions: [
        'How many files, in what window, compared with what this user normally does?',
        'Which audit trail would even record this — and is it one anybody was watching?',
        'What happened in the five minutes after the burst, and what would each part of it mean?'
      ],

      /* stage 3 — what the cadence of the sequence means */
      cadenceNote:
        'The shape is the story: a session at 08:03, an SMB connection to the file server a minute later, a ' +
        '50-file deletion burst inside five minutes, and the session gone eight minutes after that. A user ' +
        'tidying a folder does not delete ten times their own baseline and then disconnect.',

      /* ledger wording, so the analyst journal reads in the case's own terms */
      awards: {
        evidence:
          'Reviewed the full evidence set: three alerts plus user baseline and audit-trail reference data',
        timeline:
          'Identified the pattern: a deletion burst an order of magnitude over the user baseline, then departure',
        triageContext:
          'Kept the SMB connection as context rather than evidence — it frames the burst without proving intent',
        board:
          'Correlated the full chain: rneuman session → SMB to the file server → deletion burst → disconnect',
        attack: 'Mapped the outcome to ATT&CK T1485 Impact: Data Destruction',
        attackAlso: 'Identified the supporting technique: T1078.002 Valid Accounts: Domain Accounts',
        host: 'Scoped the incident to host sec-win-03'
      },

      /* stage 5 — the collapsed trail card, and its journal entry */
      trailRows: [
        { k: 'Subject', v: 'rneuman', flag: '— an ordinary domain user, not privileged' },
        { k: 'Target', v: 'Finance\\Quarterly Close', flag: '— shared folder on 10.0.4.12, 214 files before the burst' },
        { k: 'Volume', v: '50 deletes in 5 minutes', flag: '— 30-day average for this user: fewer than 5 a day' },
        { k: 'Trail', v: 'rneuman 08:03:16 → SMB 10.0.4.12:445 08:05:02 → burst 08:06:11–08:10:44 → logoff 08:11:27' }
      ],
      trailLabel: 'REVEAL THE FULL SEQUENCE',
      journalDecode:
        'Assembled the sequence — session at 08:03:16, SMB to the file server at 08:05:02, 50 deletions ' +
        'between 08:06:11 and 08:10:44, logoff at 08:11:27',

      /* stage 6 — the live assessment preview */
      reportPreview: {
        rows: [
          { label: 'Host', value: 'sec-win-03 (10.0.4.11)', code: true },
          { label: 'Account', value: 'rneuman — ordinary domain user', code: true },
          { label: 'Target', value: 'Finance\\Quarterly Close on 10.0.4.12 — 214 files, 50 now gone', code: true },
          { label: 'Rate', value: '50 deletions in 5 minutes against a 30-day average under 5 a day', code: true },
          { label: 'After', value: 'session ended 43 seconds after the last delete; no restore ticket filed', code: false },
          { label: 'TTP', value: 'Impact: Data Destruction T1485', code: false }
        ],
        note:
          'Assemble your justification in the fields above. The assessment is only defensible if the reasoning ' +
          'is visible.'
      }
    },

    /* ---------------------------------------------------------------
     * STAGE 2 — TRIAGE
     * The student tags each event as signal / context / noise.
     * tags: 'signal' | 'context' | 'noise'
     * --------------------------------------------------------------- */
    events: [
      {
        id: 'ev-4624-rneuman',
        ts: '08:03:16',
        code: 4624,
        kind: 'event',
        host: 'sec-win-03',
        actor: 'rneuman',
        text: 'Successful logon. Account "rneuman". Logon type 2 (interactive). Source 10.0.4.11.',
        tags: 'context',
        why:
          'This is the session the deletion burst will be attributed to, and nothing more. A morning logon at a ' +
          'desk is the most ordinary record on the estate \u2014 you need it to anchor the timeline, not because ' +
          'anything about it is wrong.'
      },
      {
        id: 'ev-net-smb',
        ts: '08:05:02',
        code: 'NET',
        kind: 'net',
        host: 'sec-win-03',
        text: 'Outbound connection 10.0.4.11 \u2192 10.0.4.12:445 (SMB). Share: Finance\\Quarterly Close. Initiated by rneuman session.',
        tags: 'context',
        why:
          'Opening a departmental share at 08:05 is routine, and it is not evidence of malice. It matters only ' +
          'because it fixes the route and the minute: the session reached the file server before anything was ' +
          'deleted, so the burst was not somebody else\u2019s traffic on the same wire.'
      },
      {
        id: 'ev-file-burst',
        ts: '08:06:11',
        code: 'FILE',
        kind: 'event',
        host: '10.0.4.12',
        actor: 'rneuman',
        text: 'File server audit: 50 file_delete events on Finance\\Quarterly Close between 08:06:11 and 08:10:44. Source 10.0.4.11. User rneuman.',
        tags: 'signal',
        why:
          'This is the finding, and note where it lives: it is in the file server\u2019s own audit trail, not in ' +
          'the Windows event log on the workstation. Fifty deletions inside five minutes is more than ten times ' +
          'this user\u2019s entire 30-day average for that folder \u2014 the rate is what makes it anomalous, not the ' +
          'deletion itself.'
      },
      {
        id: 'ev-4634-logoff',
        ts: '08:11:27',
        code: 4634,
        kind: 'event',
        host: 'sec-win-03',
        actor: 'rneuman',
        text: 'Logoff. Session closed for account "rneuman". Reason: user initiated.',
        tags: 'signal',
        why:
          'Forty-three seconds after the last deletion, the session ended by user action rather than by timeout ' +
          'or reboot. Ending a session immediately after a destructive act is a different picture from walking ' +
          'away from a tidy-up \u2014 it is one of the few behaviours on this list that separates the two readings.'
      },

      /* ---------- noise: baseline user activity ---------- */
      { id: 'ev-n01', ts: '08:00:29', code: 4624, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n02', ts: '08:02:04', code: 4634, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n03', ts: '08:02:51', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n04', ts: '08:03:47', code: 4624, kind: 'event', host: 'OPS-WS-09', actor: 'mchen', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n05', ts: '08:05:14', code: 4634, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n06', ts: '08:05:39', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'kpatel', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n07', ts: '08:06:48', code: 4634, kind: 'event', host: 'HR-LT-03', actor: 'asmith', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n08', ts: '08:07:52', code: 4672, kind: 'event', host: 'OPS-WS-09', actor: 'mchen', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n09', ts: '08:08:17', code: 4624, kind: 'event', host: 'FIN-LT-11', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.21.', tags: 'noise' },
      { id: 'ev-n10', ts: '08:09:28', code: 4634, kind: 'event', host: 'OPS-WS-09', actor: 'mchen', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n11', ts: '08:10:39', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'svega', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n12', ts: '08:11:47', code: 4624, kind: 'event', host: 'ENG-WS-02', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.20.', tags: 'noise' },
      { id: 'ev-n13', ts: '08:12:53', code: 4634, kind: 'event', host: 'FIN-LT-11', actor: 'svega', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n14', ts: '08:14:27', code: 4624, kind: 'event', host: 'HR-LT-03', actor: 'mchen', text: 'Successful logon. Logon type 2. Source 10.0.4.11.', tags: 'noise' },
      { id: 'ev-n15', ts: '08:16:38', code: 4634, kind: 'event', host: 'ENG-WS-02', actor: 'kpatel', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n16', ts: '08:17:12', code: 4672, kind: 'event', host: 'FIN-WS-14', actor: 'jdoe', text: 'Special privileges assigned to new logon.', tags: 'noise' },
      { id: 'ev-n17', ts: '08:19:31', code: 4624, kind: 'event', host: 'SALES-LT-11', actor: 'rneuman', text: 'Successful logon. Logon type 2. Source 10.0.4.21.', tags: 'noise' },
      { id: 'ev-n18', ts: '08:21:46', code: 4634, kind: 'event', host: 'SALES-LT-11', actor: 'rneuman', text: 'Logoff. Session closed.', tags: 'noise' },
      { id: 'ev-n19', ts: '08:24:09', code: 4624, kind: 'event', host: 'FIN-LT-11', actor: 'svega', text: 'Successful logon. Logon type 2. Source 10.0.4.10.', tags: 'noise' },
      { id: 'ev-n20', ts: '08:26:22', code: 4672, kind: 'event', host: 'HR-LT-03', actor: 'kpatel', text: 'Special privileges assigned to new logon.', tags: 'noise' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 1 — EVIDENCE INBOX
     * --------------------------------------------------------------- */
    evidence: [
      {
        id: 'al-mass-delete',
        ref: 'ALERT-01',
        severity: 'high',
        title: 'Mass file deletion on shared folder',
        blurb: "50 file delete events were recorded on file server 10.0.4.12 by user 'rneuman' within a 5-minute window. Daily baseline for this user is fewer than 5.",
        detail:
          'File server audit \u2014 50 delete operations against \\\\10.0.4.12\\Finance\\Quarterly Close between ' +
          '08:06:11 and 08:10:44, user rneuman, source 10.0.4.11. This record does not live in the Windows ' +
          'event log at all: the file server audits object access itself, which is why a workstation-side ' +
          'investigation can look completely clean while this is happening. The folder held 214 files before ' +
          'the burst.',
        hint: 'Ask: how many, how fast, and compared with what this user does on an ordinary day?'
      },
      {
        id: 'al-baseline-breach',
        ref: 'ALERT-02',
        severity: 'high',
        title: 'Deletion volume exceeds user baseline by 10x',
        blurb: "The deletion rate for 'rneuman' is more than 10 times their 30-day average for the same folder.",
        detail:
          'Behavioural comparison against the 30-day baseline for this account and this share: a median of 4 ' +
          'deletions a day, a maximum of 11, and no burst above 15 in five minutes in that period. The 30-day ' +
          'baseline for rneuman includes genuine mistakes \u2014 average 4.2 deletions a day on a folder that ' +
          'holds close-ups of documents people then regret. What has never happened before is a rate.',
        hint: 'Ask: is this user careless, or is this rate something careless never produced?'
      },
      {
        id: 'al-quick-logoff',
        ref: 'ALERT-03',
        severity: 'medium',
        title: 'User session ended immediately after deletion burst',
        blurb: "User 'rneuman' logged off sec-win-03 within 5 minutes of the deletion burst. Combined with the volume, this indicates deliberate action rather than mistake.",
        detail:
          'Security Event 4634 at 08:11:27 \u2014 43 seconds after the final delete, reason "user initiated", not ' +
          'a timeout or a workstation restart. Nobody who has just discovered they deleted the wrong folder ' +
          'logs off; they stay, and they panic in front of the keyboard. Read together with the volume, this is ' +
          'the second half of the finding.',
        hint: 'Ask: what does the reason field say, and would a surprised user end their session like that?'
      },
      {
        id: 'ev-user',
        ref: 'EVID-04',
        severity: 'info',
        title: 'Account and usage record — rneuman',
        blurb: 'Directory and file-share usage record for the account behind the deletion burst.',
        detail:
          'rneuman \u2014 R. Neumann, Commercial Analyst, 8 months in post. Group membership: Domain Users and ' +
          'Finance-Read; no write permission on the file server, and no administrative rights of any kind. ' +
          'Usage on \\\\10.0.4.12\\Finance in 30 days: 41 deletions, all single files, all before 18:00, all ' +
          'followed by a create within the same hour. 164 files created. Last password change 31 days ago.',
        hint: 'Ask: could this account delete 50 files, and does its history look like this at all?'
      },
      {
        id: 'ev-baseline',
        ref: 'EVID-05',
        severity: 'info',
        title: 'Baseline activity — other hosts this hour',
        blurb: 'Reference traffic and audit records for the estate during the same window.',
        detail:
          'Five baseline users generated 20 logon, logoff and privilege events across FIN-WS-14, HR-LT-03, ' +
          'ENG-WS-02, OPS-WS-09, FIN-LT-11 and SALES-LT-11 in this hour, all from the office floor. On the file ' +
          'server, object auditing recorded 214 delete events estate-wide in this hour; 50 of them came from ' +
          '10.0.4.11 and none of the rest came from a workstation in the finance group. No restore job ran, and ' +
          'no restore ticket was raised before 08:40.',
        hint: 'Ask: is one session an outlier, or are other users doing the same thing on their own folders?'
      }
    ],

    alerts: [
      { name: 'Mass file deletion on shared folder', severity: 'high' },
      { name: 'Deletion volume exceeds user baseline by 10x', severity: 'high' },
      { name: 'User session ended immediately after deletion burst', severity: 'medium' }
    ],

    /* ---------------------------------------------------------------
     * STAGE 3 — TIMELINE
     * --------------------------------------------------------------- */
    timeline: [
      { t: 'T+0', ts: '08:03:16', label: 'Logon', detail: 'successful_logon (4624): rneuman interactive on sec-win-03 from 10.0.4.11', net: null },
      { t: 'T+2', ts: '08:05:02', label: 'Network', detail: 'outbound SMB 10.0.4.11 \u2192 10.0.4.12:445 \u2014 Finance\\Quarterly Close opened', net: '10.0.4.11 \u2192 10.0.4.12:445' },
      { t: 'T+3', ts: '08:06:11', label: 'Deletion', detail: 'file server audit on 10.0.4.12: 50 file_delete events by rneuman, beginning 08:06:11 and running to 08:10:44', net: null },
      { t: 'T+8', ts: '08:11:27', label: 'Logoff', detail: 'user_logoff (4634): rneuman session closed by user action', net: null }
    ],

    timelineQuestion: {
      id: 'q-timeline',
      prompt: 'What pattern do you see in this sequence?',
      options: [
        { id: 'a', label: 'A user cleaning up a folder after a project closed, finishing early because the meeting moved' },
        { id: 'b', label: 'A scheduled retention job removing old close documents from a shared folder' },
        { id: 'c', label: 'A user who deleted a small number of files by mistake, logging off in a hurry to avoid a support call' },
        { id: 'd', label: 'A session that deletes far more than this user normally touches, in a compressed burst, then ends immediately afterwards' }
      ],
      correct: ['d'],
      xp: 10,
      explain:
        'Each alternative needs the rate to be wrong: cleaning up is spread over days, a retention job would run ' +
        'under a service identity on a schedule, and a small mistake followed by logging off looks nothing like ' +
        'fifty deletions in five minutes. The compression and the immediate departure are the two parts that ' +
        'matter, and they point the same way \u2014 but at what, only the evidence can settle.'
    },

    /* ---------------------------------------------------------------
     * STAGE 4 — CORRELATION BOARD
     * --------------------------------------------------------------- */
    boardNodes: [
      { id: 'n-session', label: 'sec-win-03 session', sub: 'interactive, from 10.0.4.11', x: 8, y: 8 },
      { id: 'n-user', label: 'rneuman', sub: 'ordinary domain user', x: 8, y: 62 },
      { id: 'n-share', label: 'Finance\\Quarterly Close', sub: 'shared folder', x: 40, y: 36 },
      { id: 'n-burst', label: '50 deletions', sub: 'in five minutes', x: 40, y: 82 },
      { id: 'n-fileserver', label: '10.0.4.12', sub: 'file server audit', x: 72, y: 8 },
      { id: 'n-gap', label: '164 files left', sub: 'of 214 before', x: 72, y: 62 }
    ],
    boardLinks: [
      { from: 'n-session', to: 'n-user', label: 'authenticates as', correct: true },
      { from: 'n-session', to: 'n-share', label: 'opens', correct: true },
      { from: 'n-fileserver', to: 'n-burst', label: 'records', correct: true },
      { from: 'n-burst', to: 'n-share', label: 'empties', correct: true },
      { from: 'n-burst', to: 'n-gap', label: 'leaves', correct: true },
      { from: 'n-share', to: 'n-burst', label: 'restores', correct: false },
      { from: 'n-session', to: 'n-fileserver', label: 'disconnects', correct: false }
    ],
    boardXp: 10,

    /* ---------------------------------------------------------------
     * STAGE 5 — ANALYSIS: behaviour, ATT&CK, IoCs
     * --------------------------------------------------------------- */
    behaviourQuestions: [
      {
        id: 'q-persist',
        prompt: 'How would you classify deleting 50 files from a shared folder in a five-minute burst?',
        options: [
          { id: 'a', label: 'Collection \u2014 the files were gathered up and taken somewhere' },
          { id: 'b', label: 'Impact \u2014 availability is the service being denied; the data is simply gone' },
          { id: 'c', label: 'Defense evasion \u2014 the deletions were done to cover tracks' },
          { id: 'd', label: 'Discovery \u2014 the analyst is still establishing what happened' }
        ],
        correct: ['b'],
        xp: 10,
        explain:
          'The end state is a shared resource that people need and no longer has: destruction of data, which is ' +
          'Impact. Two tempting readings are worth separating from it. Nothing left the network, so this is not ' +
          'collection or exfiltration \u2014 and if the attacker wanted to hide something, deleting the files ' +
          'would advertise it rather than conceal it. What the records cannot yet tell you is whether the ' +
          'motive was impact, an attempt to clear the path for something else, or a mistake.'
      },
      {
        id: 'q-ps',
        prompt: 'Why does the 30-day baseline matter more here than the count of 50?',
        options: [
          { id: 'a', label: 'It shows rneuman has deleted files before, so this time is not unusual' },
          { id: 'b', label: 'It converts an absolute number into a rate: 50 files in 5 minutes is something this user has never produced' },
          { id: 'c', label: 'It proves the deletions were deliberate, because careless users have no baseline' },
          { id: 'd', label: 'It shows the folder had only 50 files, so everything in it was removed' }
        ],
        correct: ['b'],
        xp: 10,
        explain:
          'Fifty deletions is a number; fifty deletions in five minutes from an account whose median is four a ' +
          'day is a behaviour. Absolute counts let someone argue "deleting files is what that folder is for", ' +
          'and the baseline is what removes that argument \u2014 the same 50 files spread over a month would be ' +
          'unremarkable. Option A is the reasoning trap: a history of mistakes is not a defence against a rate ' +
          'ten times outside anything in that history.'
      }
    ],

    decodedCommand: {
      encoded: 'rneuman 08:03:16 \u2192 SMB 10.0.4.12:445 08:05:02 \u2192 50 file deletes 08:06:11\u201308:10:44 \u2192 logoff 08:11:27',
      decoded: 'interactive session (4624) \u2192 SMB session to the file server \u2192 50 object delete operations in the server audit \u2192 user-initiated logoff (4634)',
      note:
        'Four records, and the two that matter are in different files: the workstation Security log holds the ' +
        'logon and the logoff, while the deletion lives only in the file server\u2019s object audit. An ' +
        'investigation that stops at the endpoint would find an ordinary login and a tidy logout, and would ' +
        'close the case having learned nothing.'
    },

    attack: {
      /* the engine renders primary.prompt and alsoPresent.prompt as the question text */
      primary: {
        prompt: 'Which technique best explains the outcome?',
        options: [
          { id: 'a', label: 'Data from Information Repositories', meta: 'T1213 \u00b7 Collection' },
          { id: 'b', label: 'Impact: Data Destruction', meta: 'T1485 \u00b7 Impact' },
          { id: 'c', label: 'Data Manipulation: Stored Data Manipulation', meta: 'T1565.001 \u00b7 Impact' },
          { id: 'd', label: 'Exfiltration Over Web Service', meta: 'T1567.002 \u00b7 Exfiltration' }
        ],
        correct: ['b'],
        xp: 10,
        explain:
          'Files were removed and not replaced, which is destruction of stored data and nothing else: T1485. ' +
          'The near-misses matter. T1565.001 covers altering stored data to change its meaning, and nothing here ' +
          'was altered. T1213 and T1567.002 both require data to have left the environment \u2014 the audit shows ' +
          'it did not, and the folder is measurably lighter, not exfiltrated.'
      },
      alsoPresent: {
        prompt: 'One further technique is genuinely present. Select it.',
        options: [
          { id: 'a', label: 'Valid Accounts: Domain Accounts', meta: 'T1078.002 \u00b7 Defense Evasion / Persistence' },
          { id: 'b', label: 'Scheduled Task/Job', meta: 'T1053.005 \u00b7 Execution' },
          { id: 'c', label: 'Exfiltration Over C2 Channel', meta: 'T1041 \u00b7 Exfiltration' },
          { id: 'd', label: 'Inhibit System Recovery', meta: 'T1490 \u00b7 Impact' }
        ],
        correct: ['a'],
        xp: 10,
        explain:
          'The account that did this is an ordinary domain account used exactly as it always is \u2014 no new ' +
          'account, no new credential, nothing forged \u2014 which is Valid Accounts (T1078.002), and it is the ' +
          'weakest claim in the assessment for a reason worth stating plainly: the records cannot tell you ' +
          'whether rneuman did this or somebody holding rneuman\u2019s session did. That single ambiguity is what ' +
          'separates an insider incident from an intrusion, and it is why the response questions who was at the ' +
          'keyboard before it rebuilds anything. No job was scheduled (B), nothing left the estate (C), and no ' +
          'backup was destroyed (D).'
      }
    },

    iocs: {
      prompt: 'Which of these would you preserve as indicators or investigative pivots?',
      options: [
        { id: 'i1', label: 'rneuman', role: 'indicator' },
        { id: 'i2', label: 'Finance\\Quarterly Close \u2014 214 files down to 164', role: 'indicator' },
        { id: 'i3', label: 'sec-win-03', role: 'context' },
        { id: 'i4', label: '10.0.4.12', role: 'context' },
        { id: 'i5', label: 'Event 4634', role: 'context' },
        { id: 'i6', label: 'deletion rate an order of magnitude over the account baseline', role: 'behaviour' },
        { id: 'i7', label: 'session ended seconds after the last delete', role: 'behaviour' },
        { id: 'i8', label: 'the deletion trail exists only in the file server audit', role: 'behaviour' }
      ],
      correct: ['indicator', 'behaviour', 'context'],
      xp: 10,
      explain:
        'Two of these eight are things you act on today: the account (freeze it and interview its owner before ' +
        'anything else is changed) and the exact shortfall on the folder \u2014 a precise, checkable statement of ' +
        'what was lost, and the input to any restore decision. The behaviours are the detections and the ' +
        'review gap: a deletion rate far outside an account baseline, a session that ends the moment a destructive ' +
        'burst stops, and the fact that none of this is visible in an endpoint log at all. sec-win-03, ' +
        '10.0.4.12 and Event 4634 are context \u2014 they scope the incident and open the next question, but they ' +
        'are not indicators of compromise.'
    },

    /* ---------------------------------------------------------------
     * STAGE 6 — REPORT
     * --------------------------------------------------------------- */
    report: {
      host: {
        prompt: 'Which host was the activity performed from?',
        options: [
          { id: 'a', label: 'FIN-LT-11' },
          { id: 'b', label: 'HR-LT-03' },
          { id: 'c', label: '10.0.4.12' },
          { id: 'd', label: 'sec-win-03' }
        ],
        correct: ['d'],
        xp: 10,
        explain:
          'The session that opened the share and the deletions that followed both originate on sec-win-03, ' +
          'which is also where rneuman logged on and where they logged off. 10.0.4.12 is where the files were, ' +
          'not where the activity came from \u2014 which makes it the system to restore, not the system to ' +
          'investigate.'
      },
      what: {
        prompt: 'What happened?',
        options: [
          { id: 'a', label: 'A user tidied a shared folder after a project closed and logged off early when a meeting moved.' },
          { id: 'b', label: 'A scheduled retention job removed old quarterly close documents from the shared folder.' },
          { id: 'c', label: 'A user deleted a handful of files by mistake and logged off quickly to avoid asking for help.' },
          { id: 'd', label: 'A session for rneuman opened the Finance\\Quarterly Close share on 10.0.4.12, deleted 50 of its 214 files in five minutes \u2014 more than ten times the account\u2019s 30-day rate \u2014 and then ended the session 43 seconds after the final delete, with no restore requested.' }
        ],
        correct: ['d'],
        xp: 10,
        explain:
          'The assessment has to carry the facts a responder will act on: which account, which share, how many ' +
          'and how fast, and what happened next. Volume without rate understates it, and rate without the ' +
          'immediate departure loses the second half of the finding \u2014 and this statement is deliberately ' +
          'silent on intent, because the records do not settle whether this was an insider, a mistake or the ' +
          'opening move of something larger.'
      },
      why: {
        prompt: 'Why is it suspicious? Select every reason that holds.',
        options: [
          { id: 'a', label: 'The rate was more than ten times this account\u2019s 30-day average for the same folder' },
          { id: 'b', label: 'The folder lost half its contents: 214 files down to 164' },
          { id: 'c', label: 'The session ended 43 seconds after the last delete, reason "user initiated"' },
          { id: 'd', label: 'Users delete files in shared folders every day, so some volume is expected' },
          { id: 'e', label: 'No restore was requested for four hours after the burst' },
          { id: 'f', label: 'The 30-day history shows only single-file deletions before 18:00, never a burst' }
        ],
        correct: ['a', 'b', 'c', 'e', 'f'],
        xp: 10,
        explain:
          'Five of these six are anchored to a record or a fact you were given: a rate outside any history, a ' +
          'measurable shortfall, a reason field that says user initiated, a silence where a restore should have ' +
          'been, and a history that never contained a burst. Only option D is an assumption \u2014 and it is the ' +
          'one that would close this case in an afternoon. Ordinary deletion volume is exactly what the ' +
          'baseline was established to measure against, and this is not ordinary.'
      },
      confidence: {
        prompt: 'Analyst confidence in this assessment',
        options: [
          { id: 'a', label: 'Low' },
          { id: 'b', label: 'Medium' },
          { id: 'c', label: 'High' }
        ],
        correct: ['c'],
        xp: 10,
        explain:
          'The file server audit, the behaviour baseline, the session records and the folder inventory all ' +
          'agree, and they agree on the numbers as well as the sequence. What remains genuinely open is motive ' +
          'and attribution \u2014 whether rneuman was at the keyboard \u2014 and that is an open question about ' +
          'intent, not about what happened. Confidence in the assessment should not wait on it.'
      },
      actions: {
        prompt: 'Recommended next actions. Select the three that follow from this assessment.',
        options: [
          { id: 'a', label: 'Restore the 50 deleted files from last night\u2019s backup to a quarantine location, and keep the share read-only until the scope is confirmed' },
          { id: 'b', label: 'Suspend rneuman\u2019s account and interview the account owner before touching the workstation, so the restore is not destroyed by the investigation' },
          { id: 'c', label: 'Rebuild sec-win-03 and every other workstation in the finance group as a precaution' },
          { id: 'd', label: 'Enable object-level auditing for delete operations on every file share estate-wide, and alert on bursts above an account baseline' },
          { id: 'e', label: 'Audit the folder\u2019s access list to see who else could have deleted the same 50 files' },
          { id: 'f', label: 'Close the case as an accidental deletion once the files are restored' }
        ],
        correct: ['a', 'd', 'e'],
        xp: 10,
        explain:
          'Stop the bleeding, then close the blind spot. Restoring to quarantine \u2014 rather than straight back ' +
          'into the live share \u2014 keeps the evidence if this turns out to be deliberate, and read-only buys ' +
          'time while scope is confirmed. Object-level auditing with a rate-based alert is the fix for why this ' +
          'was only found by chance: nothing was watching the deletion trail at all. And the access list answers ' +
          'the scope question \u2014 whether 10.0.4.11 was the only route in. Options C and F both destroy ' +
          'something important: the first wipes the only host that can say who was at the keyboard, the second ' +
          'closes a case whose cause is still unknown.'
      }
    },

    reasoning: {
      prompt: 'Which three pieces of evidence most strongly support your assessment? Select exactly three.',
      options: [
        { id: 'r1', label: 'rneuman is not a member of any administrative group', key: false },
        { id: 'r2', label: 'File server audit: 50 delete operations against Finance\\Quarterly Close between 08:06:11 and 08:10:44, source 10.0.4.11', key: true },
        { id: 'r3', label: 'Five baseline users were active elsewhere in the estate during the same hour', key: false },
        { id: 'r4', label: 'Behavioural comparison: a rate more than ten times the account\u2019s 30-day average, and no comparable burst in that period', key: true },
        { id: 'r5', label: 'Event 4624 and 4634 are among the most common events on the estate', key: false },
        { id: 'r6', label: 'Event 4634: the session closed by user action 43 seconds after the final delete, and no restore was requested for four hours', key: true },
        { id: 'r7', label: 'The folder sits on the busiest file server in the estate', key: false }
      ],
      correctCount: 3,
      xp: 10,
      explain:
        'The three that count are the volume itself, the rate it was measured against, and what happened straight ' +
        'afterwards \u2014 and they come from two different systems, which is what makes them corroborate rather ' +
        'than repeat each other. The others describe background: ordinary users doing ordinary things, common ' +
        'event codes, and a busy server. None of them would change what you concluded if you removed them, which ' +
        'is the test for evidence.'
    },

    /* mirrored verbatim from new.scenario — the dotted keys are kept as written
       there, because this block is the record of what the case is actually made of */
    ground_truth: {
      file_delete_events: 50,
      fileserver_contacted: '10.0.4.12',
      user_responsible: 'rneuman',
      target_host: 'sec-win-03',
      event_ids_present: [4624, 4634]
    },

    ranking: [
      { min: 90, rank: 'Lead Intelligence Analyst', note: 'You produced defensible intelligence, not just correct answers.' },
      { min: 75, rank: 'Threat Intelligence Analyst', note: 'Strong correlation and a defensible judgment.' },
      { min: 55, rank: 'Junior CTI Investigator', note: 'You found the burst and explained it. Tighten the correlation and the reporting.' },
      { min: 0, rank: 'Case Officer Trainee', note: 'Re-run the case. Start in the file server audit, not in the workstation event log \u2014 the deletion is not in the latter.' }
    ],

    assist: {
      nudge: { label: 'Nudge', mult: 0.85, text: 'Stop counting files and start measuring them. Compare the burst to what this account does on an ordinary Tuesday.' },
      hint: { label: 'Analyst Hint', mult: 0.7, text: 'One record gives you the volume, one tells you whether that volume is normal, and one tells you what the user did afterwards.' },
      explain: { label: 'Explain', mult: 0.5, text: 'rneuman logged on to sec-win-03 at 08:03:16, opened \\\\10.0.4.12\\Finance\\Quarterly Close over SMB at 08:05:02, and the file server\u2019s object audit recorded 50 delete operations between 08:06:11 and 08:10:44 \u2014 more than ten times that account\u2019s 30-day average for the folder, which fell from 214 files to 164. The session closed by user action at 08:11:27, 43 seconds later, and no restore was requested for four hours. The outcome is Impact: Data Destruction, T1485, with Valid Accounts: Domain Accounts (T1078.002) as the weakest of the claims \u2014 the records cannot tell you whether rneuman was at the keyboard. Note that the deletion exists only in the file server audit, which is why an endpoint-only investigation would have found nothing.' }
    }
  });
})();