use xcore::JourneyId;

use super::*;

/// A page a wake brought: told apart by its clock.
fn woken() -> DueQueue {
    DueQueue {
        read_unix_nanos: 7,
        ..DueQueue::default()
    }
}

fn queued(journey: u128) -> Queued {
    Queued {
        journey: JourneyId::new(journey),
        at: (0, 3),
        places: Vec::new(),
    }
}

#[test]
fn a_first_read_begins_at_the_start_with_a_wakes_page_and_a_later_one_where_reads_went() {
    let mut reading = Reading::default();
    assert!(!reading.goes_on() && !reading.wants(), "nothing asked");
    reading.asked(Some(woken()));
    assert!(reading.goes_on() && reading.wants());
    let read = reading.reads();
    assert_eq!(read.read, Some(((0, 0), Some(woken()))), "the wake's page");
    reading.went(Some(Went::On(None)), (Some(40), false));
    assert!(!reading.goes_on(), "read to its end");
    reading.asked(Some(woken()));
    let read = reading.reads();
    assert_eq!(
        read.read,
        Some(((0, 40), None)),
        "what arrived since, asked"
    );
    assert_eq!(read.fresh, 40);
}

#[test]
fn asked_while_a_read_is_under_way_it_reads_on_once_that_ends() {
    let mut reading = Reading::default();
    reading.asked(None);
    let _ = reading.reads();
    reading.went(Some(Went::On(Some((0, 64)))), (Some(64), false));
    reading.asked(None);
    assert_eq!(
        reading.reads().read,
        Some(((0, 64), None)),
        "on from its cursor"
    );
    reading.went(Some(Went::On(None)), (Some(90), false));
    assert_eq!(
        reading.reads().read,
        Some(((0, 90), None)),
        "again, from where it went"
    );
    reading.went(Some(Went::On(None)), (None, false));
    assert!(!reading.goes_on(), "asked nothing since: it ends");
}

#[test]
fn a_starved_read_goes_on_from_the_entry_that_found_no_place_once_one_frees() {
    let mut reading = Reading::default();
    reading.asked(None);
    let _ = reading.reads();
    reading.held = 2;
    reading.went(Some(Went::Starved((0, 7))), (Some(7), false));
    assert!(!reading.goes_on(), "it waits for a place");
    assert!(reading.wants(), "its share is still wanted");
    assert!(reading.reads().read.is_none(), "nothing while starved");
    reading.freed();
    assert_eq!(reading.reads().read, Some(((0, 7), None)));
}

#[test]
fn a_periodic_scan_reads_every_head_and_what_arrived_never_from_a_wake() {
    let mut reading = Reading::default();
    reading.asked(None);
    let _ = reading.reads();
    reading.went(Some(Went::On(None)), (Some(12), false));
    reading.park(queued(1));
    reading.asked(Some(woken()));
    reading.afresh();
    let read = reading.reads();
    assert!(read.every, "every head read again");
    assert_eq!(read.again, [queued(1)], "what is loose taken up again");
    assert_eq!(
        read.read,
        Some(((0, 12), None)),
        "what arrived, read afresh"
    );
}

#[test]
fn a_read_storage_does_not_answer_ends_until_the_next_ask_and_goes_on_where_reads_went() {
    let mut reading = Reading::default();
    reading.asked(None);
    let _ = reading.reads();
    reading.went(Some(Went::On(Some((0, 64)))), (Some(64), false));
    reading.asked(None);
    reading.went(Some(Went::Unanswered), (None, false));
    assert!(!reading.goes_on() && !reading.wants(), "ended, again too");
    reading.asked(None);
    assert_eq!(reading.reads().read, Some(((0, 64), None)));
}

#[test]
fn what_is_loose_is_taken_up_again_once_asked_and_one_at_once_where_another_was_written() {
    let mut reading = Reading::default();
    reading.park(queued(1));
    reading.park(queued(2));
    assert!(!reading.goes_on(), "loose waits to be asked");
    reading.again_now(JourneyId::new(2));
    assert_eq!(reading.reads().again, [queued(2)], "that one at once");
    reading.loosen();
    assert_eq!(reading.reads().again, [queued(1)]);
    assert!(!reading.goes_on());
}
