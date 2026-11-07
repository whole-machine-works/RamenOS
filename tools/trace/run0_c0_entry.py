"""Pure, opaque prior-entry correspondence proof; never a live-read grant.

Only exact retained native bytes enter the existing profile-binding proof. No
filesystem resolver, socket, VM launch or caller-provided address is accepted.
Python observer internals are trusted and do not establish a security boundary.
"""
from dataclasses import dataclass
import re

import run0_c0_decode as decoder


@dataclass(frozen=True, slots=True, init=False)
class ValidatedPriorEntry:
    profile_ref: tuple
    probe_profile_sha256: str
    prior_admission_ref: tuple
    profile_mapping_ref: tuple
    entry_address: int
    loaded_base: int
    diagnostic_ref: tuple
    diagnostic_line: int
    prior_run_id: str
    expected_entry_hex: str
    invocation_profile: str
    scope: str

    def __init__(self, *args, **kwargs):
        raise TypeError('use validate_prior_entry on exact retained evidence')


def _native_ref(value):
    decoder._require(type(value) is dict and all(type(key) is str for key in value),
                     'prior_entry_ref_type')
    return decoder._ref(dict.copy(value), 65536)


def _freeze_ref(value):
    return (value['path'], value['sha256'], value['length'])


def _export_ref(value):
    decoder._require(type(value) is tuple and len(value) == 3, 'prior_entry_ref_fields')
    return _native_ref(dict(zip(('path', 'sha256', 'length'), value)))


def export_validated_prior_entry(token):
    """Return fresh native dictionaries only for this exact immutable token type."""
    decoder._require(type(token) is ValidatedPriorEntry, 'prior_entry_token_type')
    names = ('profile_ref', 'probe_profile_sha256', 'prior_admission_ref', 'profile_mapping_ref',
             'entry_address', 'loaded_base', 'diagnostic_ref', 'diagnostic_line', 'prior_run_id',
             'expected_entry_hex', 'invocation_profile', 'scope')
    try:
        result = {name: getattr(token, name) for name in names}
    except AttributeError as error:
        raise decoder.C0DecodeError('DENY', 'prior_entry_token_fields') from error
    for name in ('profile_ref', 'prior_admission_ref', 'profile_mapping_ref', 'diagnostic_ref'):
        result[name] = _export_ref(result[name])
    for name, pattern in (('probe_profile_sha256', '[0-9a-f]{64}'),
                          ('prior_run_id', '[a-z0-9-]{1,64}'), ('expected_entry_hex', '[0-9a-f]{64}')):
        decoder._require(type(result[name]) is str and re.fullmatch(pattern, result[name]) is not None,
                         'prior_entry_token_' + name)
    decoder._integer(result['entry_address'])
    decoder._integer(result['loaded_base'])
    decoder._require(result['loaded_base'] % 4096 == 0, 'prior_entry_token_base_alignment')
    decoder._integer(result['diagnostic_line'], 1, 65536)
    decoder._require(type(result['scope']) is str and result['scope'] == 'prior-run-hint-only',
                     'prior_entry_token_scope')
    decoder._require(type(result['invocation_profile']) is str and result['invocation_profile'] in (
        decoder.capture.INVOCATION_PROFILE, decoder.capture.SATA_OFF_INVOCATION_PROFILE,
        decoder.capture.VAPIC_OFF_INVOCATION_PROFILE), 'prior_entry_token_invocation_profile')
    return result


def validate_prior_entry(profile_ref, prior_admission_ref, profile_mapping_ref, blobs):
    """Recompute a sole prior candidate without acquiring bytes or granting reads.

    Copy and bound the complete three-ref envelope before looking at any blob.
    Missing referenced bytes are INCOMPLETE; present contradictory evidence DENY.
    The token can be reused across fresh sessions of the same reviewed profile.
    Its proof does not bind borrowed sockets to an actual owned VM launch.
    """
    report = {name: _native_ref(value) for name, value in (
        ('profile_ref', profile_ref), ('prior_admission_ref', prior_admission_ref),
        ('profile_mapping_ref', profile_mapping_ref))}
    store = decoder._Blobs(blobs)
    # Register all three identities before parsing. Repeated paths must agree;
    # the shared store also checks every transitively referenced identity.
    for value in report.values():
        store.get(value, 65536)
    try:
        profile, _, candidate = decoder._profile_binding(report, store)
    except decoder.capture.ProbeError as error:
        raise decoder.C0DecodeError(error.status, error.reason) from error
    except decoder.entry.UnavailableInput as error:
        # A saved ADMIT with a candidate contradicts a present diagnostic that
        # cannot supply one sole matching record. Missing blobs failed above.
        raise decoder.C0DecodeError('DENY', 'prior_diagnostic_invalid') from error
    except decoder.entry.AdmissionError as error:
        raise decoder.C0DecodeError('DENY', 'prior_admission_invalid') from error
    values = {**report, 'probe_profile_sha256': decoder.entry.profile_digest(profile),
              'invocation_profile': profile['invocation_profile'], **candidate}
    token = object.__new__(ValidatedPriorEntry)
    for name, value in values.items():
        if name in ('profile_ref', 'prior_admission_ref', 'profile_mapping_ref', 'diagnostic_ref'):
            value = _freeze_ref(value)
        object.__setattr__(token, name, value)
    export_validated_prior_entry(token)
    return token
