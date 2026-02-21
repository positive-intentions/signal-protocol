#!/usr/bin/env perl
# Patch X3dh extraction to handle Result-wrapped values
use strict;
use warnings;
local $/;
my $content = <>;

# Add unwrap definitions after NotImplementedYet
$content =~ s/\(\* NotImplementedYet \*\)/
(* NotImplementedYet *)

Definition simple_ecdh_unwrap a b := unwrap_ok (simple_ecdh a b).
Definition hkdf_derive_unwrap a b c d := unwrap_ok (hkdf_derive a b c d).
/;

# Replace simple_ecdh and hkdf_derive calls with unwrapped versions
$content =~ s/simple_ecdh \(/simple_ecdh_unwrap (/g;
$content =~ s/hkdf_derive \(/hkdf_derive_unwrap (/g;

# Remove 'run (' wrapper and matching closing paren from both functions
# The X3dh functions don't use ControlFlow at all, just Result
$content =~ s/:=\s+run \(let dh1/:=\n  let dh1/g;

# Remove Result_Ok wrappers around dh_concat in match arms  
# Pattern: Result_Ok (let dh_concat := ... in\n    dh_concat)
$content =~ s/Result_Ok \(let dh_concat := (.*?) in\s+dh_concat\)/let dh_concat := $1 in\n    dh_concat/gs;

# Pattern: Result_Ok (dh_concat)
$content =~ s/Result_Ok \(dh_concat\)/dh_concat/g;

# Remove the outer Result_Ok that was wrapping the whole body inside run()
# Now the function returns: Result_Ok (let assoc... in Result_Ok (X3DHResult ...)))
# We need to collapse to: let assoc... in Result_Ok (X3DHResult ...)
# i.e. remove the outer Result_Ok and its closing paren

# Now we have: ... Result_Ok (let associated_data := [...] in\n  Result_Ok (X3DHResult (...) (...)))). 
# Remove outer Result_Ok and extra closing paren from removed run(
$content =~ s/Result_Ok \(let associated_data := (.*?) in\s+Result_Ok \((X3DHResult [^.]+?\))\)\)\)\./let associated_data := $1 in\n  Result_Ok ($2)./gs;

print $content;
