"""Focused regression checks for the review's interpreter and research contracts."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from pipeline import diagnostics, evaluate as ev, freeze, run_llm, static_baseline as sb


def fixture(operations):
    instructions = [dict(address=hex(0x1000 + 16*i), mnemonic=m, operands=o)
                    for i, (m, o) in enumerate(operations)]
    return dict(schema_version=1, architecture='x86-64',
                function=dict(name='example', entry='0x1000', end=hex(0x1000 + 16*len(operations))),
                instructions=instructions, calls=[], decompilation=dict(status='ok', text='void example(void) {}'))


class InterpreterRegressionTests(unittest.TestCase):
    def test_popped_frame_slot_can_be_reused(self):
        record = fixture([('push','RBP'), ('mov','RBP,RSP'), ('pop','RBP'), ('sub','RSP,0x10'),
                          ('mov','qword ptr [RSP + 0x8],0x0'), ('add','RSP,0x10'), ('ret','')])
        self.assertEqual(sb.analyze_record(record)['decision'], 'uncertain')

    def test_real_overwrite_remains_after_slot_is_popped(self):
        for epilogue in ([('pop','RBP')], [('leave','')]):
            record = fixture([('push','RBP'), ('mov','RBP,RSP'), ('mov','qword ptr [RSP],0x0'),
                              *epilogue, ('ret','')])
            self.assertEqual(sb.analyze_record(record)['decision'], 'vulnerable_CWE-121')

    def test_repeated_predicate_cannot_take_contradictory_branches(self):
        record = fixture([('test','EDI,EDI'), ('je','0x1060'), ('test','EDI,EDI'), ('je','0x1050'),
                          ('jmp','0x1060'), ('mov','qword ptr [RSP],0x0'), ('ret','')])
        self.assertFalse(any(state.stack_writes for state in sb.follow_paths(record)))
        self.assertEqual(sb.analyze_record(record)['decision'], 'uncertain')

    def test_unvalidated_branch_cannot_prove_stack_or_heap_overflow(self):
        record = fixture([('test','EDI,EDI'), ('je','0x1030'), ('ret',''),
                          ('mov','qword ptr [RSP],0x0'), ('ret','')])
        self.assertEqual(sb.analyze_record(record)['decision'], 'uncertain')
        state = sb.State(path_validated=False)
        state.allocations['0x1000'] = dict(size=1, writes=[(0, 2, '0x1010')], validated_writes=[],
                                          complete=True, freed=False)
        self.assertIsNone(sb.classify_heap([state]))

    def test_register_write_invalidates_predicate_identity(self):
        record = fixture([('test','EDI,EDI'), ('je','0x1070'), ('mov','EDI,0'),
                          ('test','EDI,EDI'), ('je','0x1060'), ('ret',''),
                          ('mov','qword ptr [RSP],0x0'), ('ret','')])
        self.assertTrue(any(state.stack_writes for state in sb.follow_paths(record)))
        # Exploration still does not establish feasibility of the initial fork.
        self.assertEqual(sb.analyze_record(record)['decision'], 'uncertain')

    def test_stack_overwrite_before_unknown_branch_remains_proven(self):
        record = fixture([('mov','qword ptr [RSP],0'), ('test','EDI,EDI'),
                          ('je','0x1040'), ('nop',''), ('ret','')])
        result = sb.analyze_record(record)
        self.assertEqual(result['decision'], 'vulnerable_CWE-121')
        self.assertEqual(result['evidence'], ['0x1000'])

    def test_heap_overwrite_before_unknown_branch_keeps_only_proven_evidence(self):
        record = fixture([('mov','EDI,1'), ('call','0x2000'),
                          ('mov','word ptr [RAX],0'), ('test','ESI,ESI'),
                          ('je','0x1060'), ('mov','qword ptr [RAX + 0x8],0'), ('ret','')])
        record['calls'] = [dict(address='0x1010', target='malloc')]
        result = sb.analyze_record(record)
        self.assertEqual(result['decision'], 'vulnerable_CWE-122')
        self.assertEqual(result['evidence'], ['0x1010', '0x1020'])
        self.assertIn('[0, 2)', result['summary'])
        self.assertNotIn('[8, 16)', result['summary'])

    def test_safe_heap_prefix_does_not_validate_later_speculative_overflow(self):
        record = fixture([('mov','EDI,1'), ('call','0x2000'),
                          ('mov','byte ptr [RAX],0'), ('test','ESI,ESI'),
                          ('je','0x1060'), ('mov','word ptr [RAX],0'), ('ret','')])
        record['calls'] = [dict(address='0x1010', target='malloc')]
        self.assertEqual(sb.analyze_record(record)['decision'], 'uncertain')


class ScoringRegressionTests(unittest.TestCase):
    def test_indivisible_cwe_abstention_and_unavailability(self):
        self.assertEqual(ev.score_three_way('vulnerable_CWE-121','vulnerable_CWE-122'), 'incorrect')
        self.assertEqual(ev.score_forced_alert('vulnerable_CWE-121','vulnerable_CWE-122'), 'tp')
        self.assertEqual(ev.score_three_way('not_vulnerable','uncertain'), 'abstain')
        self.assertEqual(ev.score_forced_alert('not_vulnerable','uncertain'), 'tn')
        self.assertEqual(ev.score_three_way('not_vulnerable',ev.UNAVAILABLE), 'unavailable')

    def test_failures_do_not_vote_and_median_pools_valid_runs(self):
        valid = lambda label, confidence: dict(status='valid', parsed=dict(decision=label, confidence=confidence))
        failure = dict(status='length_limit', parsed=None)
        result = ev.aggregate_three_runs([valid('not_vulnerable',.9), valid('not_vulnerable',.8), failure])
        self.assertEqual(result['decision'], 'not_vulnerable')
        self.assertAlmostEqual(result['confidence'], .85)
        self.assertEqual(result['unavailable_runs'], 1)
        self.assertEqual(ev.aggregate_three_runs([failure]*3)['decision'], ev.UNAVAILABLE)
        self.assertEqual(ev.aggregate_three_runs([valid('not_vulnerable',.9), valid('uncertain',.2), failure])['decision'], ev.AGREEMENT_UNCERTAIN)

    def test_shared_weights_produce_exact_zero_contrast_for_identical_methods(self):
        truth = [dict(observation_id='r0001',pair_id='a',truth='not_vulnerable'),
                 dict(observation_id='r0002',pair_id='b',truth='vulnerable_CWE-121')]
        predictions = {'r0001':dict(decision='not_vulnerable'), 'r0002':dict(decision='uncertain')}
        weights = ev.bootstrap_weights(['a','b'], 100, 12)
        context = ev.context(truth, predictions, ['a','b'], weights)
        rows = ev.paired_difference(context, context, 'x', 'overall', 'all', 'x', 'y', 100)
        for row in rows:
            if row['bootstrap_defined']:
                self.assertEqual((row['ci_low'], row['ci_high']), (0., 0.))
        np.testing.assert_array_equal(weights.sum(axis=1), 2)

    def test_collision_exclusions_do_not_depend_on_predictions(self):
        record = fixture([('ret','')])
        truth = [dict(observation_id='r0001',truth='not_vulnerable'),
                 dict(observation_id='r0002',truth='vulnerable_CWE-121')]
        result = diagnostics.collisions(truth, {'r0001': record, 'r0002': copy.deepcopy(record)})
        self.assertEqual(result['conflicting_ids'], ['r0001', 'r0002'])
        self.assertEqual(result['consistent_classifier_exact_label_ceiling'], 1)

    def test_static_predictions_are_recomputed(self):
        record = fixture([('ret','')])
        prediction = dict(observation_id='r0001', **sb.analyze_record(record))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'results').mkdir()
            path = root/'results/static_predictions.jsonl'
            path.write_text(json.dumps(prediction)+'\n')
            with patch.object(ev,'PROJECT_ROOT',root):
                ev.load_static_predictions({'r0001':record})
                prediction['summary'] = 'Forged but schema valid'
                path.write_text(json.dumps(prediction)+'\n')
                with self.assertRaisesRegex(ValueError, 'frozen implementation'):
                    ev.load_static_predictions({'r0001':record})


class FreezeRegressionTests(unittest.TestCase):
    def test_analyzer_inventory_rejects_missing_extra_and_nested_records(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = freeze.FINAL_RECORDS | freeze.RUNTIME_FILES | {
                'config.json', 'llm/prompt.md', 'llm/response.schema.json', 'pipeline/run_llm.py',
                'pipeline/extract.py', 'pipeline/runtime.py', 'pipeline/serve_llm.py', 'pipeline/freeze.py',
            }
            for name in names:
                path = root/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{}\n')
            hashes = freeze.hash_files(root, names)
            hashes.update({name: '0'*64 for name in freeze.PRIVATE_FILES})
            (root/freeze.FREEZE_PATH).write_text(json.dumps(dict(freeze_version=2, files=hashes)))
            # No private files exist: the analyzer must not open them.
            freeze.check_analyzer_inputs(root)
            for name in ('r0161.json', 'nested/r0001.json'):
                extra = root/'data/records'/name
                extra.parent.mkdir(parents=True, exist_ok=True)
                extra.write_text('{}\n')
                with self.assertRaisesRegex(ValueError, 'record inventory changed'):
                    freeze.check_analyzer_inputs(root)
                extra.unlink()
            (root/'data/records/r0080.json').unlink()
            with self.assertRaisesRegex(ValueError, 'record inventory changed'):
                freeze.check_analyzer_inputs(root)

    def test_private_mutation_detected_and_existing_freeze_never_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'data/private').mkdir(parents=True)
            (root/'results').mkdir()
            names = {'data/private/observations.csv', 'data/private/manual_oracle.csv', 'record.json'}
            for name in names:
                (root/name).write_text('original\n')
            with patch.object(freeze,'expected_files',return_value=names):
                freeze.create_freeze(root)
                freeze.check_freeze(root)
                for name in names:
                    (root/name).write_text('mutated\n')
                    with self.assertRaisesRegex(ValueError,'Frozen inputs changed'):
                        freeze.check_freeze(root)
                    (root/name).write_text('original\n')
                with self.assertRaisesRegex(ValueError,'already exists'):
                    freeze.create_freeze(root)

    def test_cannot_create_freeze_after_inference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'results/llm_runs').mkdir(parents=True)
            (root/'results/llm_runs/campaign.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'retrospective freeze'):
                freeze.ensure_campaign_not_started(root)

class RunnerFailureTests(unittest.TestCase):
    def test_alternate_inputs_are_rejected_before_runtime_or_inference(self):
        from pipeline import runtime
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            alternate = root/'alternate'
            alternate.mkdir()
            (alternate/'r0001.json').write_text(json.dumps(fixture([('ret','')])))
            output = root/'output'
            with patch.object(run_llm, 'PROJECT_ROOT', root), \
                 patch.object(runtime, 'verify_live') as live, \
                 patch.object(run_llm, 'run_attempt') as attempt:
                with self.assertRaisesRegex(ValueError, "this campaign's frozen"):
                    run_llm.main(['--inputs', str(alternate), '--output', str(output)])
                live.assert_not_called()
                attempt.assert_not_called()
                self.assertFalse(output.exists())

    def test_length_failure_is_saved_even_with_schema_valid_answer(self):
        from types import SimpleNamespace
        record = fixture([('ret','')])
        output = dict(decision='uncertain', confidence=.4, evidence=[], summary='No bounds available.')
        response = SimpleNamespace(status_code=200, text=json.dumps({
            'choices':[{'message':{'content':json.dumps(output)}, 'finish_reason':'length'}],
            'usage':{'prompt_tokens':10,'completion_tokens':4096}}))
        config, schema = run_llm.load_config(), run_llm.load_schema()
        payload = run_llm.make_payload(record, run_llm.load_prompt(), schema, config, 1)
        with patch.object(run_llm,'send_request',return_value=response):
            run = run_llm.run_attempt('r0001',1,record,payload,config,schema)
        self.assertEqual(run['status'],'length_limit')
        self.assertIsNone(run['parsed'])
        self.assertEqual(run['response_body'],response.text)
        self.assertEqual(run['raw_response'],json.dumps(output))
        self.assertEqual(run['usage']['completion_tokens'],4096)

    def test_every_sampler_setting_is_bound_to_request_hash(self):
        import hashlib
        config = run_llm.load_config()
        payload = run_llm.make_payload(fixture([('ret','')]), run_llm.load_prompt(),run_llm.load_schema(),config,1)
        before = hashlib.sha256(run_llm.canonical_json(payload).encode()).hexdigest()
        config['sampling']['top_k'] += 1
        changed = run_llm.make_payload(fixture([('ret','')]),run_llm.load_prompt(),run_llm.load_schema(),config,1)
        self.assertNotEqual(before,hashlib.sha256(run_llm.canonical_json(changed).encode()).hexdigest())
        for key,value in config['sampling'].items():
            self.assertEqual(changed[key],value)


class RuntimeIdentityTests(unittest.TestCase):
    def test_live_server_property_and_process_substitution_are_rejected(self):
        from pipeline import runtime
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'runtime').mkdir()
            config = {'llm':{'base_url':'http://127.0.0.1:8080'}}
            props = dict(model_alias='m',model_path='/model',build_info='build',total_slots=1,
                         default_generation_settings={'n_ctx':8192},chat_template='template')
            identity = dict(pid=123,start_ticks='42',binary_sha256='abc')
            evidence = dict(process=identity,props=props,model_stat={'st_size':100})
            (root/'config.json').write_text(json.dumps(config))
            (root/'runtime/server.json').write_text(json.dumps(evidence))
            with patch.object(runtime.serve_llm,'server_command',return_value=['server','--model','/model']), \
                 patch.object(runtime,'process_identity',return_value=identity) as process, \
                 patch.object(runtime,'model_stat',return_value={'st_size':100}), \
                 patch.object(runtime,'owns_listener',return_value=True) as listener, \
                 patch.object(runtime,'request',return_value=props) as request:
                runtime.verify_live(root)
                request.return_value = {**props,'chat_template':'substituted'}
                with self.assertRaisesRegex(ValueError,'properties changed'):
                    runtime.verify_live(root)
                request.return_value = props
                process.return_value = {**identity,'start_ticks':'43'}
                with self.assertRaisesRegex(ValueError,'identity changed'):
                    runtime.verify_live(root)
                process.return_value = identity
                listener.return_value = False
                with self.assertRaisesRegex(ValueError,'own the configured listener'):
                    runtime.verify_live(root)
