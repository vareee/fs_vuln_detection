use fs_vuln_detection::*;

fn main() {
    // example of safe transcript
    match safe_transcript_example() {
        Ok(msg) => println!("{}", msg),
        Err(e) => println!("{}", e),
    }
    println!("----------------");

    // example of transcript with TranscriptError
    match transcript_error_example() {
        Ok(msg) => println!("{}", msg),
        Err(e) => println!("{}", e),
    }
    println!("----------------");

    // example of cross transcript interaction with error
    match cross_transcript_interaction_example() {
        Ok(msg) => println!("{}", msg),
        Err(e) => println!("{}", e),
    }
    println!("----------------");

    // example of cross round object ineraction with error
    match cross_round_interaction_example() {
        Ok(msg) => println!("{}", msg),
        Err(e) => println!("{}", e),
    }
    println!("----------------");

    // example of interaction with not constants
    match non_constant_interaction_example() {
        Ok(msg) => println!("{}", msg),
        Err(e) => println!("{}", e),
    }
    println!("----------------");

    // example of transcript that does not contain every prover's message
    let params = setup(2, 4);
    match forge_bulletproof(&params) {
        Ok(_proof) => println!("No Fiat-Shamir heuristic vulnerability detected."),
        Err(e) => println!("Detected: {}", e),
    }
}
