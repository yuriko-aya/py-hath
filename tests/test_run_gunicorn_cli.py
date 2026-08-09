"""CLI tests for run_gunicorn.py."""

from run_gunicorn import _build_arg_parser


def test_force_rescan_flag():
    args = _build_arg_parser().parse_args(['--force-rescan'])
    assert args.force_rescan is True
    assert args.stop_after_init is False


def test_stop_after_init_flag():
    args = _build_arg_parser().parse_args(['--stop-after-init'])
    assert args.stop_after_init is True
    assert args.force_rescan is False


def test_force_rescan_and_stop_after_init():
    args = _build_arg_parser().parse_args(['--force-rescan', '--stop-after-init'])
    assert args.force_rescan is True
    assert args.stop_after_init is True
