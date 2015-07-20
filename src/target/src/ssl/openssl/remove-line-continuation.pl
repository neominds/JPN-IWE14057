#!/usr/bin/perl -w
#
# Copyright 2004 Wind River Systems, Inc.
#
# modification history
# --------------------
# 01a, 18mar04,cdw    		written
#
# DESCRIPTION
# Helper script for gen-makefile.sh.  This file extracts the list of
# .o files from the existing OpenSSL makefiles for inclusion into the
# new Wind River makefiles.
#
#*/
$found_objs = 0;

while (defined ($line = <STDIN>) ) {
  chomp $line;
  if ($line =~ s/^\s*L?I?B?OBJ\s*=\s*/OBJS = \t/) {
    print "$line\n";
    $found_objs = 1;
    while ($line =~ /\\$/ ) {
      $line = <STDIN>;
      chomp $line;
      $line =~ s/^\s*/\t/;
      print "$line\n";
    }
  }
}

if ($found_objs == 0) {
  exit 1; # didn't find an OBJ= line in stdin
}
