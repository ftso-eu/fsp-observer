from collections.abc import Sequence

from py_flare_common.fsp.messaging.byte_parser import ByteParser
from py_flare_common.fsp.messaging.types import (
    FdcSubmit1,
    FdcSubmit2,
    SubmitSignatures,
)

from ..message import Message, MessageBuilder, MessageLevel
from ..reward_epoch_manager import Entity
from ..types import ProtocolMessageRelayed
from ..voting_round import VotingRound, WParsedPayload
from .signature import Signature
from .types import ValidateFn


# NOTE:(matej) stupid type cast
def _check_type(f: ValidateFn[FdcSubmit1, FdcSubmit2, SubmitSignatures]):
    return f


@_check_type
def check_submit_1(
    submit_1: WParsedPayload[FdcSubmit1] | None,
    message_builder: MessageBuilder,
    **_,
) -> Sequence[Message]:
    issues = []
    mb = message_builder

    # NOTE:(matej) In fdc protocol submit1 is not used.
    # we perform the following checks:
    # - submit1 exists -> error

    if submit_1 is not None:
        issues.append(mb.build(MessageLevel.ERROR, "found submit1 transaction"))

    return issues


@_check_type
def check_submit_2(
    submit_2: WParsedPayload[FdcSubmit2] | None,
    message_builder: MessageBuilder,
    round: VotingRound,
    **_,
) -> Sequence[Message]:
    issues = []
    mb = message_builder

    # NOTE:(matej) In fdc protocol submit2 is used for sending the bit vote
    # this means that the messsage must exist. Additionally decoded bit vote must have
    # length matching the number of requests in the round and bit vote must dominate
    # consensus bit vote.
    # we perform the following checks:
    # - submit2 doesnt't exist -> error
    # - submit2 exists but bit vote length doesn't match number of requests -> error
    # - submit2 exists but bit vote does not dominate consensus bit vote -> error

    # TODO:(matej) move this to py-flare-common
    bp = ByteParser(
        sorted(round.fdc.consensus_bitvote.items(), key=lambda x: -x[1])[0][0]
    )
    n_requests = bp.uint16()
    votes = bp.drain()
    consensus_bitvote = [False for _ in range(n_requests)]
    for j, byte in enumerate(reversed(votes)):
        for shift in range(8):
            i = n_requests - 1 - j * 8 - shift
            if i < 0 and (byte >> shift) & 1 == 1:
                raise ValueError("Invalid payload length.")
            elif i >= 0:
                consensus_bitvote[i] = (byte >> shift) & 1 == 1

    sorted_requests = round.fdc.requests.sorted()
    assert len(sorted_requests) == n_requests

    if submit_2 is None:
        issues.append(mb.build(MessageLevel.ERROR, "no submit2 transaction"))

    if submit_2 is not None:
        bit_vector = submit_2.parsed_payload.payload.bit_vector
        if len(bit_vector) != len(sorted_requests):
            issues.append(
                mb.build(
                    MessageLevel.ERROR,
                    "submit2 bit vote length didn't match number of requests in round",
                )
            )
        else:
            for i, (r, bit, cbit) in enumerate(
                zip(sorted_requests, bit_vector, consensus_bitvote)
            ):
                idx = n_requests - 1 - i
                at = r.attestation_type
                si = r.source_id

                if cbit and not bit:
                    issues.append(
                        mb.build(
                            MessageLevel.ERROR,
                            "submit2 didn't confirm request that was part of consensus "
                            f"{at.representation}/{si.representation} at index {idx}",
                        )
                    )

    return issues


@_check_type
def check_submit_signatures(
    submit_2: WParsedPayload[FdcSubmit2] | None,
    submit_signatures: WParsedPayload[SubmitSignatures] | None,
    finalization: ProtocolMessageRelayed | None,
    message_builder: MessageBuilder,
    entity: Entity,
    round: VotingRound,
    **_,
) -> Sequence[Message]:
    issues = []
    mb = message_builder

    # NOTE:(matej) In fdc protocol submitSignatures is used for sending the signature
    # of finalization struct (ProtocolMessageRelayed event on chain). This means that
    # the message must exist and the signature must match the finalization. Additionally
    # the signature must be deposited before the end of grace period or finalization on
    # chain (whichever is later)
    # we perform the following checks:
    # - submit2 doesn't exist and submitSignatures doesn't exist -> error
    # - submit2 exists and submitSignatures doesn't exist and submit2 bit vote
    #   dominates consensus bit vote -> reveal offence
    # - submitSignature was sent after the deadline -> warning
    # - signature doesn't match finalization -> error

    if submit_2 is None and submit_signatures is None:
        issues.append(
            mb.build(MessageLevel.ERROR, "no submitSignatures transaction"),
        )

    if submit_2 is not None and submit_signatures is None:
        # TODO:(matej) move this to py-flare-common
        bp = ByteParser(
            sorted(round.fdc.consensus_bitvote.items(), key=lambda x: -x[1])[0][0]
        )
        n_requests = bp.uint16()
        votes = bp.drain()
        consensus_bitvote = [False for _ in range(n_requests)]
        for j, byte in enumerate(reversed(votes)):
            for shift in range(8):
                i = n_requests - 1 - j * 8 - shift
                if i < 0 and (byte >> shift) & 1 == 1:
                    raise ValueError("Invalid payload length.")
                elif i >= 0:
                    consensus_bitvote[i] = (byte >> shift) & 1 == 1

        bit_vector = submit_2.parsed_payload.payload.bit_vector

        submit_2_correct_length = len(bit_vector) == n_requests
        submit_2_dominates = all(
            b or not cb for b, cb in zip(bit_vector, consensus_bitvote)
        )

        if submit_2_correct_length and submit_2_dominates:
            issues.append(
                mb.build(
                    MessageLevel.CRITICAL,
                    "no submitSignatures transaction, causing reveal offence",
                ),
            )

    if submit_signatures is not None:
        deadline = max(
            round.voting_epoch.next.start_s + 55,
            (finalization and finalization.timestamp) or 0,
        )
    
#    NOT USEFUL WARNINGS
#        if submit_signatures.wtx_data.timestamp > deadline:
#            issues.append(
#                mb.build(
#                    MessageLevel.WARNING,
#                    "no submitSignatures during grace period, causing loss of rewards",
#                )
#            )

    if submit_signatures is not None and finalization is not None:
        s = Signature.from_parsed_signature(
            submit_signatures.parsed_payload.payload.signature
        )
        addr = s.recover_public_key_from_msg_hash(
            finalization.to_message()
        ).to_checksum_address()

        if addr != entity.signing_policy_address:
            issues.append(
                mb.build(
                    MessageLevel.ERROR,
                    "submitSignatures signature doesn't match finalization",
                ),
            )

    return issues
