"""Published pilot predictions replay from public bundles and saved IR without private artifacts."""
from redesign.pipeline import baseline_snapshot
from redesign.pipeline.baseline_history import replay_v1


def test_pilot_snapshot_replays_without_ghidra_builds_sources_or_oracle(monkeypatch):
    monkeypatch.delenv('GHIDRA_HOME',raising=False)
    def forbidden(*args):raise AssertionError('Replay must not invoke private preparation or Ghidra')
    monkeypatch.setattr(baseline_snapshot,'verify',forbidden)
    original=baseline_snapshot.read_json;opened=[]
    def read(path):
        opened.append(str(path));return original(path)
    monkeypatch.setattr(baseline_snapshot,'read_json',read)
    result=baseline_snapshot.replay()
    assert result=={'status':'verified','planned_observations':32,'replayed_predictions':32}
    assert not any('/corpus/' in path or '/build/' in path for path in opened)


def test_previous_revision_replays_with_its_preserved_method_and_schema():
    assert replay_v1()=={'status':'verified','planned_observations':32,'replayed_predictions':32}
