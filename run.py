import sys
import json

from src.utils import prep_dir, clean_raw, clean_features, clean_processed
from src.data.get_data import get_data
from src.features.build_features import build_features
from src.models import hindroid

DATA_PARAMS = 'config/data-params.json'
TEST_PARAMS = 'config/test-params.json'


def load_params(fp):
    with open(fp) as fh:
        param = json.load(fh)

    return param


def main(targets):
    # make the data target
    if 'data' in targets:
        cfg = load_params(DATA_PARAMS)
    elif 'data-test' in targets:
        cfg = load_params(TEST_PARAMS)
    elif 'test-project' in targets:
        cfg = load_params(TEST_PARAMS)
        prep_dir(**cfg)
        clean_raw(**cfg)
        clean_features(**cfg)
        clean_processed(**cfg)
        prep_dir(**cfg)
        get_data(**cfg)
        build_features(**cfg)
        hindroid.run(**cfg)
        return
    else:
        return

    prep_dir(**cfg)

    # make the clean target
    if 'clean' in targets:
        clean_raw(**cfg)
        clean_features(**cfg)
        clean_processed(**cfg)
        return

    # make the data target
    if 'ingest' in targets:
        get_data(**cfg)

    if 'process' in targets:
        build_features(**cfg)

    if 'model' in targets:
        hindroid.run(**cfg)

    return


if __name__ == '__main__':
    targets = sys.argv[1:]
    main(targets)
