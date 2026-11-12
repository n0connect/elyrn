// Fuzz: frontend/js/pow-worker.js, loaded as a classic script whose global object is `self`, as
// in a dedicated worker. Task shapes are judged against an independent rule and the server's own
// hex patterns (backend/internal/contract/patterns.go); the hand-written SHA-256 and leading-zero
// count against Node's; low-difficulty tasks are really solved and the answer verified.
// Run: node --test frontend/tests/*.fuzz.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { fuzz, load, plain, goPatterns, goHexExact } from './fuzz-helpers.mjs';

const SEED = 0x5eed0007;
const TASK_ITERATIONS = 5000;
const HASH_ITERATIONS = 2000;
const SOLVE_ITERATIONS = 40;
const MAX_SOLVED_DIFFICULTY = 8;
const SERVER_MAX_DIFFICULTY = 24; // backend config maxPoWDifficulty
const TASK_BYTES = 16;            // pow.ChallengeBytes and pow.SaltBytes
const HASH_BITS = 256;

// The context's global object is `self`, as in a dedicated worker
const globals = { TextEncoder };
globals.self = globals;
const worker = load(globals, ['../js/pow-worker.js']);
const context = worker.context;
const go = goPatterns();
const GO_CHALLENGE = goHexExact(go, TASK_BYTES);

const sha256 = (text) => createHash('sha256').update(text).digest('hex');

// The rule, written independently of the worker's
function wellFormed(task) {
    const hex = new RegExp(`^[0-9a-f]{${TASK_BYTES * 2}}$`);
    return task !== null && typeof task === 'object' && typeof task.challenge === 'string' && hex.test(task.challenge) &&
        typeof task.salt === 'string' && hex.test(task.salt) && Number.isInteger(task.difficulty) &&
        task.difficulty >= 1 && task.difficulty <= SERVER_MAX_DIFFICULTY;
}

function leadingZeroBits(hex) {
    let bits = 0;
    for (const digit of hex) {
        const value = parseInt(digit, 16);
        if (value === 0) {
            bits += 4;
            continue;
        }
        return bits + Math.clz32(value) - 28;
    }
    return bits;
}

function taskOf(r) {
    const task = { challenge: r.hex(TASK_BYTES * 2), salt: r.hex(TASK_BYTES * 2), difficulty: r.int(1, SERVER_MAX_DIFFICULTY) };
    const roll = r.next();
    if (roll < 0.3) return task;
    if (roll < 0.9) {
        const field = r.pick(['challenge', 'salt', 'difficulty']);
        task[field] = field === 'difficulty' ? r.value(0) : r.bool() ? r.mutate(task[field]) : r.value(0);
        return task;
    }
    return r.value();
}

// Runs the worker's handler on data and returns what it posted
function post(data) {
    const posted = [];
    context.postMessage = (message) => posted.push(plain(message));
    context.onmessage({ data });
    return posted;
}

test('isValidTask: the independent rule exactly; a valid task fits the server\'s hex patterns and bounds the budget', async () => {
    const isValidTask = worker.get('isValidTask');
    const attemptBudget = worker.get('attemptBudget');
    await fuzz(SEED, TASK_ITERATIONS, (r) => {
        const task = taskOf(r);
        const valid = isValidTask(task);
        assert.equal(valid, wellFormed(task), `isValidTask(${JSON.stringify(task)})`);
        if (!valid) return;
        assert.match(task.challenge, GO_CHALLENGE);
        assert.match(task.salt, GO_CHALLENGE);
        const budget = attemptBudget(task.difficulty);
        assert.ok(Number.isSafeInteger(budget) && budget > 2 ** task.difficulty && budget <= attemptBudget(SERVER_MAX_DIFFICULTY));
    });
});

test('sha256 and hasNLeadingZeros agree with Node and an independent count', async () => {
    const workerSha = worker.get('sha256');
    const hasNLeadingZeros = worker.get('hasNLeadingZeros');
    await fuzz(SEED + 1, HASH_ITERATIONS, (r) => {
        const input = r.string();
        const digest = sha256(input);
        assert.equal(workerSha(input), digest, `input of length ${input.length}`);
        const n = r.int(-1, HASH_BITS + 1);
        assert.equal(hasNLeadingZeros(digest, n), leadingZeroBits(digest) >= n, `n=${n} on ${digest}`);
    });
});

test('onmessage: a malformed task gets one failure saying nothing; a valid one is solved and verifies', async () => {
    await fuzz(SEED + 2, SOLVE_ITERATIONS, (r) => {
        const task = taskOf(r);
        if (wellFormed(task)) task.difficulty = r.int(1, MAX_SOLVED_DIFFICULTY); // solvable fast
        const posted = post(task);
        const last = posted[posted.length - 1];
        if (!wellFormed(task)) {
            assert.deepEqual(posted, [{ success: false, error: worker.get('FAILURE_TEXT'), attempts: 0 }]);
            return;
        }
        assert.equal(last.success, true);
        assert.match(last.solution, /^(0|[1-9][0-9]*)$/);
        assert.ok(leadingZeroBits(sha256(task.challenge + last.solution + task.salt)) >= task.difficulty);
        for (const progress of posted.slice(0, -1)) assert.equal(progress.progress, true);
    });
});
