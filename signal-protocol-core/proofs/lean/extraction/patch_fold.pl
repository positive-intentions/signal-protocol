#!/usr/bin/env perl
use strict;
use warnings;

local $/;
my $content = <>;
# Match the full fold block - use [\s\S] to match across newlines, non-greedy
my $pattern = qr/let ⟨removed_count, state⟩ ←\s+\(core_models\.iter\.traits\.iterator\.Iterator\.fold\s+\(← \(core_models\.iter\.traits\.collect\.IntoIterator\.into_iter[\s\S]*?keys_to_remove\)\)\)\)\s+\(rust_primitives\.hax\.Tuple2\.mk removed_count state\)\s+\(fun ⟨removed_count, state⟩ key =>[\s\S]*?RustM \(rust_primitives\.hax\.Tuple2 usize DoubleRatchetState\)\)\)\);/;
my $replacement = 'let ⟨removed_count, state⟩ ←
      (pure (rust_primitives.hax.Tuple2.mk removed_count state));';
$content =~ s/$pattern/$replacement/s;
print $content;
