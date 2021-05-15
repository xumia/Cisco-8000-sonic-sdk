# BEGIN_LEGAL
#
# Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

use strict;
use List::Util qw(min max);

my $sv_config;

# tables
my $Native_L2_LP        = Table->new("Native_L2_LP",        type_size => 4, narrow_size => 24, wide_size => 48, protected_size => 41);
my $Native_LB           = Table->new("Native_LB",           type_size => 4, narrow_size => 49);
my $Native_FEC          = Table->new("Native_FEC",          type_size => 4, narrow_size => 56);
my $Native_FRR          = Table->new("Native_FRR",          type_size => 4, protected_size => 52);
my $Path_LB             = Table->new("Path_LB",             type_size => 3, narrow_size => 29);
my $Path_LP             = Table->new("Path_LP",             type_size => 3, narrow_size => 20, wide_size => 40, protected_size => 34);
my $Stage3_LB           = Table->new("Stage3_LB",           type_size => 2, narrow_size => 40);
my $Port_NPP_Protection = Table->new("Port_NPP_Protection", type_size => 2, protected_size => 40);
my $Port_DSPA           = Table->new("Port_DSPA",           type_size => 1, narrow_size => 15);

# Values
my $enc_type     = Value->new("enc_type",      4);
my $L3_DLP       = Value->new("L3_DLP",       16);
my $TE_Tunnel16b = Value->new("TE_Tunnel16b", 16);
my $TE_Tunnel14b = Value->new("TE_Tunnel14b", 14);
my $VPN_INTER_AS = Value->new("VPN_INTER_AS",  2);
my $ASBR         = Value->new("ASBR",         15);
my $DLP_ATTR     = Value->new("dlp_attr",      6);
my $Overlay_NH   = Value->new("Overlay_NH",   10);
my $IP_Tunnel    = Value->new("IP_Tunnel",    16);
my $pad_2        = Value->new("00",            2);
my $pad_3        = Value->new("000",           3);
my $pad_4        = Value->new("0000",          4);
my $pad_6        = Value->new("000000",        6);
my $pad_7        = Value->new("0000000",       7);
my $pad_12       = Value->new("000000000000", 12);
my $pad_16       = Value->new("000........0", 16);
my $pad_20       = Value->new("000........0", 20);
my $pad_24       = Value->new("000........0", 24);
my $pad_25       = Value->new("000........0", 25);
my $pad_27       = Value->new("000........0", 27);
my $pad_29       = Value->new("000........0", 29);
my $pad_39       = Value->new("000........0", 39);
my $pad_44       = Value->new("000........0", 44);

# Destinations
#                                                              19    16      12       8       4       0
my $full_destination = Destination->new("Destination",      [qw/- - - - - - - - - - - - - - - - - - - -/]);

# NPU end point destinations
my $BVN              = Destination->new("BVN",              [qw/1 1 1 1 - - - - - - - - - - - - - - - -/]);
my $MC               = Destination->new("MC",               [qw/1 1 1 0 - - - - - - - - - - - - - - - -/]);
# my $FLBG             = Destination->new("FLBG",             [qw/0 1 0 1 1 0 - - - - - - - - - - - - - -/]); $FLBG->{nbits} = 16;
my $DSP              = Destination->new("DSP",              [qw/0 1 0 1 1 x x x - - - - - - - - - - - -/]);
my $GLEAN            = Destination->new("GLEAN",            [qw/0 1 0 1 1 0 1 x x x x x x x x x x - - -/]);

# First Stage FEC
my $FEC              = Destination->new("FEC",              [qw/0 1 0 1 0 x x x - - - - - - - - - - - -/], $Native_FEC );
# my $L3_DLP        = Destination->new("L3_DLP",             [qw/0 1 0 0 0 - - - - - - - - - - - - - - -/]); moved to value

# First Stage FRR - Unused
my $FRR_Protection   = Destination->new("FRR_Protection",   [qw/1 1 0 0 1 x x x x x x x - - - - - - - -/], $Native_FRR );

# First Stage ECMP/EM - L2_DLPA and ECMP share the same prefix. TODO avbehar: remove L2_DLPA altogether
my $L2_DLPA          = Destination->new("L2_DLPA",          [qw/0 1 1 0 0 x x - - - - - - - - - - - - -/], $Native_LB  );
my $ECMP             = Destination->new("ECMP",             [qw/0 1 1 0 0 x x - - - - - - - - - - - - -/], $Native_LB  );

# First Stage Direct
my $CE_PTR           = Destination->new("CE_PTR",           [qw/0 0 x x - - - - - - - - - - - - - - - -/], $Native_L2_LP); $CE_PTR->{nbits} = 18;
my $DPE              = Destination->new("DPE",              [qw/0 0 x x - - - - - - - - - - - - - - - -/], $Native_L2_LP); $DPE->{nbits} = 16;
my $L3_VPN           = Destination->new("L3_VPN",           [qw/0 0 1 0 - - - - - - - - - - - - - - - -/]);
my $L2_DLP           = Destination->new("L2_DLP",           [qw/1 0 - - - - - - - - - - - - - - - - - -/], $Native_L2_LP);

# Second Stage ECMP/EM
my $Stage2_ECMP      = Destination->new("Stage2_ECMP",      [qw/0 1 1 0 1 x x - - - - - - - - - - - - -/], $Path_LB       );

# Second Stage Direct
my $Stage2_P_NH      = Destination->new("Stage2_P_NH",      [qw/0 1 1 1 1 x x x - - - - - - - - - - - -/], $Path_LP       );
my $Stage2_P_NH_11b  = Destination->new("Stage2_P_NH_11b",  [qw/0 1 1 1 1 x x x x - - - - - - - - - - -/], $Path_LP       );

# Third Stage ECMP/EM
my $Stage3_NH        = Destination->new("Stage3_NH",        [qw/1 1 0 0 0 x x x - - - - - - - - - - - -/], $Stage3_LB);
my $Stage3_NH_11b    = Destination->new("Stage3_NH_11b",    [qw/1 1 0 0 0 x x x x - - - - - - - - - - -/], $Stage3_LB);

# Fourth Stage ECMP/EM
my $DSPA             = Destination->new("DSPA",             [qw/0 1 1 1 0 x x - - - - - - - - - - - - -/], $Port_DSPA);

# Fourth Stage Direct
my $Tunnel1_DLP      = Destination->new("Tunnel1_DLP",      [qw/1 1 0 1 0 x x x x x - - - - - - - - - -/], $Port_NPP_Protection);

# Non-Resolution destination2
my $L3_DLP_Subnet    = Destination->new("L3_DLP_Subnet",    [qw/0 1 0 0 - - - - - - - - - - - - - - - -/]);
my $LPTS             = Destination->new("LPTS",             [qw/0 1 1 1 0 x x x x x x x - - - - - - - -/]);
my $IP_Prefix_ID     = Destination->new("IP_Prefix_ID",     [qw/0 0 1 - - - - - - - - - - - - - - - - -/]);
my $BD               = Destination->new("BD",               [qw/1 1 1 0 - - - - - - - - - - - - - - - -/]);

my %resolution =
   (
    # temporary so that some values will be defined
    FRR_Protection_Placeholder => {
        start => $FRR_Protection,
        FRR_Protection => {
            protected => $FRR_Protection,
            destination => $DSP,
        },
    },
    NPP_Prot => { # NPP_Protection_Placeholder
        start => $Tunnel1_DLP,
        Tunnel1_DLP => {
            protected => $Tunnel1_DLP,
            destination => $DSP,
        },
    },

    DSPA => { # used by "all" applications
        start => [$DSPA],
        DSPA => {
            destination => $DSP,
        },
    },
    AC => {
        start => [$L2_DLPA, $L2_DLP],
        encap_data => [[$enc_type, $L2_DLP]],
        L2_DLPA => {
            destination => $L2_DLP,
        },
        L2_DLP => {
            destination => [$DSP, $DSPA, $BVN],
            start_encapsulation => "NPU_ENCAP_L2_HEADER_TYPE_AC",
            protected => $L2_DLP,
        },
    },
    Mpls_Head => {
        start => [$FEC, $ECMP, $CE_PTR],
        encap_data => [[$enc_type, $L3_DLP, $Stage3_NH, $CE_PTR, $pad_20, $pad_3, $DLP_ATTR],
                       [$enc_type, $L3_DLP, $Stage3_NH, $CE_PTR, $TE_Tunnel16b, $pad_7, $DLP_ATTR],
                       [$enc_type, $L3_DLP, $Stage3_NH, $CE_PTR, $TE_Tunnel14b, $pad_7,  $DLP_ATTR],
                       [$enc_type, $L3_DLP, $Stage3_NH_11b, $VPN_INTER_AS, $DPE, $ASBR, $pad_7, $DLP_ATTR]],
        FEC => {
            op1 => {
                destination => $CE_PTR,
            },
        },
        ECMP => {
            op1 => {
                destination => $CE_PTR,
            },
            op2 => {
                destination => $DPE,
            },
        },
        CE_PTR => {
            op1 => {
                destination => [$Stage3_NH, $Stage2_P_NH],
                start_encapsulation => "NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE",
                protected => $CE_PTR,
            },
            op2 => {
                destination => $Stage2_ECMP,
                protected => $CE_PTR,
            },
            op3 => {
                destination => [$Stage3_NH, $Stage2_P_NH],
                start_encapsulation => "NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID",
                encapsulation => $TE_Tunnel16b,
                protected => $CE_PTR,
            },
        },
        DPE => {
            op1 => {
                destination => $Stage2_ECMP,
                use_index => $DPE,
                encapsulation => [$VPN_INTER_AS]
            },
        },
        Stage2_ECMP => {
            op1 => {
                destination => [$Stage3_NH, $Stage2_P_NH],
                start_encapsulation => "NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE",
            },
            op2 => {
                destination => [$Stage3_NH, $Stage2_P_NH],
                start_encapsulation => "NPU_ENCAP_L3_HEADER_TYPE_TE_HE_WITH_TUNNEL_ID",
                encapsulation => $TE_Tunnel14b,
            },
            op3 => {
                destination => [$Stage3_NH, $Stage2_P_NH],
                start_encapsulation => "NPU_ENCAP_L3_HEADER_TYPE_LDP_OVER_TE",
                encapsulation => $TE_Tunnel14b,
            },
            op4 => {
                destination => [$Stage3_NH_11b, $Stage2_P_NH_11b],
                start_encapsulation => "NPU_ENCAP_L3_HEADER_TYPE_MPLS_HE",
                encapsulation => [$ASBR],
            },
        },
        Stage2_P_NH => {
            op1 => {
                destination => $Stage3_NH,
                protected => $Stage3_NH,
            },
        },
        Stage3_NH => {
            op1 => {
                destination => [$DSP, $DSPA, $BVN],
                encapsulation => [$L3_DLP, $DLP_ATTR],
                protected => $Stage3_NH,
            },
            op2 => {
                destination => [$GLEAN],
                encapsulation => [$L3_DLP],
            },
        },
    },
    Mpls_Midpoint => {
        start => [$Stage2_P_NH],
        encap_data => [[$enc_type, $L3_DLP, $Stage3_NH, $pad_20, $TE_Tunnel16b, $pad_3, $DLP_ATTR]],
        Stage2_P_NH => {
            op1 => {
                destination => $Stage3_NH,
                protected => $Stage3_NH,
            },
            op2 => {
                destination => $Stage3_NH,
                start_encapsulation => "NPU_ENCAP_L3_HEADER_TYPE_ILM_TUNNEL",
                encapsulation => $TE_Tunnel16b,
                protected => $Stage3_NH,
            },
        },
        Stage3_NH => {
            op1 => {
                destination => [$DSP, $DSPA, $BVN],
                encapsulation => [$L3_DLP, $DLP_ATTR],
                protected => $Stage3_NH,
            },
            op2 => {
                destination => [$GLEAN],
                encapsulation => [$L3_DLP],
            },
        },
    },
    Basic_Router => {
        start => [$FEC, $ECMP, $Stage2_ECMP],
        encap_data => [[$enc_type, $L3_DLP, $Stage3_NH, $pad_39, $DLP_ATTR],
                       [$enc_type]],
        FEC => {
            op1 => {
                destination => $Stage3_NH,
                start_encapsulation => "NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH",
            },
            #op2 => {
            #    destination => $FLBG,
            #    start_encapsulation => "NPU_ENCAP_L3_HEADER_TYPE_FLB",
            #},
            op3 => {
                destination => $Stage2_ECMP,
            },
        },
        ECMP => {
            op1 => {
                destination => $Stage3_NH,
                start_encapsulation => "NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH",
            },
            op2 => {
                destination => $Stage2_ECMP,
            },
        },
        Stage2_ECMP => {
            op1 => {
                destination => $Stage3_NH,
                start_encapsulation => "NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH",
            },
        },
        Stage3_NH => {
            op1 => {
                destination => [$DSP, $DSPA, $BVN],
                encapsulation => [$L3_DLP, $DLP_ATTR],
                protected => $Stage3_NH,
            },
            op2 => {
                destination => [$GLEAN],
                encapsulation => [$L3_DLP],
            },
        },
    },
    VxLAN => {
        start => [$FEC, $L2_DLP, $L2_DLPA],
        encap_data => [[$enc_type, $L3_DLP, $Stage3_NH, $L2_DLP, $Overlay_NH, $pad_29, $DLP_ATTR]],
        FEC => {
            op1 => {
                destination => [$L2_DLPA, $L2_DLP],
            },
        },
        L2_DLPA => {
            op1 => {
                destination => $L2_DLP,
            },
        },
        L2_DLP => {
            op1 => {
                destination => $Stage2_ECMP,
                start_encapsulation => "NPU_ENCAP_L2_HEADER_TYPE_VXLAN",
                encapsulation => [$Overlay_NH],
                use_index => $L2_DLP,
            },
            op2 => {
                destination => $Stage3_NH,
                start_encapsulation => "NPU_ENCAP_L2_HEADER_TYPE_VXLAN",
                encapsulation => [$Overlay_NH],
                use_index => $L2_DLP,
            },
        },
        Stage2_ECMP => {
            op1 => {
                destination => $Stage3_NH,
            },
        },
        Stage3_NH => {
            op1 => {
                destination => [$DSP, $DSPA],
                encapsulation => [$L3_DLP, $DLP_ATTR],
                use_index => $Stage3_NH,
            },
            op2 => {
                destination => [$GLEAN],
                encapsulation => [$L3_DLP],
            },
        },
    },
    GRE => {
        start => [$ECMP, $CE_PTR],
        encap_data => [[$enc_type, $L3_DLP, $Stage3_NH, $IP_Tunnel, $pad_27, $DLP_ATTR]],
        ECMP => {
            op1 => {
                destination => [$CE_PTR],
            },
        },
        CE_PTR => {
            op1 => {
                destination => $Stage2_ECMP,
                start_encapsulation => "NPU_ENCAP_L3_HEADER_TYPE_GRE",
                encapsulation => [$IP_Tunnel],
            },
            op2 => {
                destination => $Stage3_NH,
                start_encapsulation => "NPU_ENCAP_L3_HEADER_TYPE_GRE",
                encapsulation => [$IP_Tunnel],
            },
        },
        Stage2_ECMP => {
            op1 => {
                destination => $Stage3_NH,
            },
        },
        Stage3_NH => {
            op1 => {
                destination => [$DSP, $DSPA],
                encapsulation => [$L3_DLP, $DLP_ATTR],
                use_index => $Stage3_NH,
            },
            op2 => {
                destination => [$GLEAN],
                encapsulation => [$L3_DLP],
            },
        },
    },
);

# print resolution structure

open(OUTFILE, ">", "resolution_types.npl") or die "can't open resolution_types.npl";

printf OUTFILE "// --------------------------------------------------------------------------------\n";
printf OUTFILE "// debug summary:\n";

foreach my $app (sort keys %resolution) {
    printf OUTFILE "// application: $app\n";
    my $r_app = Application->new($app);
    foreach my $destination (sort keys %{$resolution{$app}}) {
        if ($destination eq "start") {
            $r_app->{start} = $resolution{$app}{start};
            next;
        }
        if ($destination eq "encap_data") {
            foreach my $encap_data (sort @{$resolution{$app}{encap_data}}) {
                $r_app->add_encap_data($encap_data);
            }
            next;
        }
        printf OUTFILE "//  destination: $destination\n";

        my $common_start_encapsulation = $resolution{$app}{$destination}{start_encapsulation};
        $common_start_encapsulation = "" unless defined ($common_start_encapsulation);

        my @common_destination =   merge($resolution{$app}{$destination}{destination});
        my @common_encapsulation = merge($resolution{$app}{$destination}{encapsulation});
        my $common_protected = $resolution{$app}{$destination}{protected};
        my $common_use_index = $resolution{$app}{$destination}{use_index};

        my $has_option = 0;
        foreach my $op (sort keys %{$resolution{$app}{$destination}}) {
            if ($op =~ /^op/) {
                printf OUTFILE "//    $op:\n";
                my $start_encapsulation = $resolution{$app}{$destination}{$op}{start_encapsulation};
                $start_encapsulation = $common_start_encapsulation unless defined ($start_encapsulation);

                my @destination =   merge($resolution{$app}{$destination}{$op}{destination},   @common_destination);
                my @encapsulation = merge($resolution{$app}{$destination}{$op}{encapsulation}, @common_encapsulation);

                my $protected = $resolution{$app}{$destination}{$op}{protected};
                printf OUTFILE "ERROR: only one protected field\n" if (defined($protected) and defined($common_protected));
                $protected = $common_protected if not defined $protected;

                my $use_index = $resolution{$app}{$destination}{$op}{use_index};
                $use_index = $common_use_index if not defined $use_index;

                printf OUTFILE "//       start_encapsulation:   $start_encapsulation\n";
                printf OUTFILE "//       destination:           "; print_list(@destination);
                printf OUTFILE "//       encapsulation:         "; print_list(@encapsulation);
                printf OUTFILE "//       protected:             $protected->{name}\n" if defined $protected;
                printf OUTFILE "//       use_index:             $use_index->{name}\n" if defined $use_index;

                add_formats($r_app, $destination, $start_encapsulation, @destination, @encapsulation, $protected, $use_index);

                $has_option = 1;
            }
        }
        if ($has_option == 0) {
            printf OUTFILE "//       start_encapsulation: $common_start_encapsulation\n";
            printf OUTFILE "//       destination:         "; print_list(@common_destination);
            printf OUTFILE "//       encapsulation:       "; print_list(@common_encapsulation);
            printf OUTFILE "//       protected:           $common_protected->{name}\n" if defined $common_protected;
            printf OUTFILE "//       use_index:           $common_use_index->{name}\n" if defined $common_use_index;

            add_formats($r_app, $destination, $common_start_encapsulation, @common_destination, @common_encapsulation, $common_protected, $common_use_index);
        }
    }
}

printf OUTFILE "// Sort:\n";

# sort format list
@Format::formats = sort {$a->{destination}->{name} cmp $b->{destination}->{name} ||
                         $a->{resolved_destination}->{name} cmp $b->{resolved_destination}->{name} ||
                         $a->{encapsulation}->cmp_str() cmp $b->{encapsulation}->cmp_str() ||
                         $a->get_app_names_str() cmp $b->get_app_names_str() } @Format::formats;


printf OUTFILE "// %s\n", Format->get_str("header_row");
foreach my $format (@Format::formats) {
    printf OUTFILE "// %s\n", $format->get_str();
}

# remove duplicates
my @filtered_formats;
my %seen;
foreach my $format (@Format::formats) {

#   print "testing format->get_str() = *", $format->get_str(), "*\n";
    # *********     THIS MANUALLY REMOVES FORMATS    *************** "
    if ($seen{$format->cmp_str()}) {
        $seen{$format->cmp_str()}->add_app(@{$format->{app}}[0]);
#       print "seen format->cmp_str() = ", $format->cmp_str(), "\n";
    }
    else {
        $seen{$format->cmp_str()} = $format;
        push @filtered_formats, $format;
#       print "new format->cmp_str() = ", $format->cmp_str(), "\n";
    }
}

foreach my $format (@filtered_formats) {
    $format->calc_format();
}

@filtered_formats = sort {$a->{destination}->{name} cmp $b->{destination}->{name} ||
                          $a->{format} cmp $b->{format} ||
                          $a->{size} cmp $b->{size} ||
                          $a->{resolved_destination}->{name} cmp $b->{resolved_destination}->{name} ||
                          $a->{encapsulation}->cmp_str() cmp $b->{encapsulation}->cmp_str()} @filtered_formats;


printf OUTFILE "// \n";
printf OUTFILE "// \n";
printf OUTFILE "// \n";
printf OUTFILE "// Filtered formats:\n";


printf OUTFILE "// %s\n", Format->get_str("header_row");
foreach my $format (@filtered_formats) {
    printf OUTFILE "// %s\n", $format->get_str();
}


# filter again
# ------------

my @formats = @filtered_formats;
@filtered_formats = ();
%seen = {};
foreach my $format (@formats) {
    if ($seen{$format->cmp_str()}) {
        foreach my $app (sort @{$format->{app}}) {
            $seen{$format->cmp_str()}->add_app($app);
        }

        $seen{$format->cmp_str()}->add_destination(${$format->{destinations}}[0]);
    }
    else {
        $seen{$format->cmp_str()} = $format;
        push @filtered_formats, $format;
    }
}

printf OUTFILE "// \n";
printf OUTFILE "// \n";
printf OUTFILE "// \n";
printf OUTFILE "// Filtered formats (after destination expansion):\n";

printf OUTFILE "// %s\n", Format->get_str("header_row");
foreach my $format (@filtered_formats) {
    printf OUTFILE "// %s\n", $format->get_str();
}



printf OUTFILE "// --------------------------------------------------------------------------------\n";
printf OUTFILE "\n";

# print encapsulation data per applicatoin
printf OUTFILE "// encapsulation data per application\n";
printf OUTFILE "//\n";
foreach my $app (@Application::applications) {
    printf OUTFILE "// $app->{name} encapsulation data:\n";

    foreach my $e (sort {$a->get_str() cmp $b->get_str()} grep { defined } @{$app->{encap_data}}) {
        printf OUTFILE "//   %s\n", join ", ", map(sprintf("%s(%d @ %d)", $_->{name}, $_->{nbits}, $_->{start}), @{$e->{list}});
    }

    printf OUTFILE "\n";
}

# print some encodings
my $max = max map {length($_->{name})} values %Destination::destinations;

printf OUTFILE "\n";
printf OUTFILE "// Destination encoding:\n";
printf OUTFILE "//\n";
foreach my $destination (sort {$b->{enc_str} cmp $a->{enc_str} || $a->{name} cmp $b->{name}} values %Destination::destinations) {
    printf OUTFILE "//   %-".$max."s : %s\n", $destination->{name}, $destination->{enc_str};
}
printf OUTFILE "\n";
foreach my $destination (sort {$b->{enc_str} cmp $a->{enc_str} || $a->{name} cmp $b->{name}} values %Destination::destinations) {
    my $mask = $destination->{enc_str};
    $mask =~ s/x/0/g;
    $mask =~ s/-/0/g;
    printf OUTFILE "constant DESTINATION_MASK_%-".$max."s 20'b%s;\n", uc($destination->{name}), $mask;
}
printf OUTFILE "\n";

foreach my $destination (sort {$b->{enc_str} cmp $a->{enc_str} || $a->{name} cmp $b->{name}} values %Destination::destinations) {
    my $prefix = $destination->{enc_str};
    $prefix =~ s/x//g;
    $prefix =~ s/-//g;
    next if length($prefix) == 0;
    printf OUTFILE "constant DESTINATION_%-".($max+7)."s %d'b%s;\n", uc($destination->{name})."_PREFIX", length($prefix), $prefix;
}
printf OUTFILE "\n";

foreach my $destination (sort {$b->{enc_str} cmp $a->{enc_str} || $a->{name} cmp $b->{name}} values %Destination::destinations) {
    my $prefix = $destination->{enc_str};
    $prefix =~ s/x//g;
    $prefix =~ s/-//g;
    next if length($prefix) == 0;
    my $prefix_len_bits = (length($prefix) < 8) ? 3 : 4;
    printf OUTFILE "constant DESTINATION_%-".($max+11)."s ".$prefix_len_bits."'d%s; // DESTINATION_%-".($max+7)."s %d'b%s\n",
           uc($destination->{name})."_PREFIX_LEN",
           length($prefix),
           uc($destination->{name})."_PREFIX",
           length($prefix), $prefix;
}
printf OUTFILE "\n";

# print some formats

## sort the formats by the app name.

@filtered_formats = sort {$a->get_entry_format_str() cmp $b->get_entry_format_str() ||
                          $a->get_app_names_str()    cmp $b->get_app_names_str()    ||

                          $a->get_destination_names_str() cmp $b->get_destination_names_str() ||
                          $a->{destination}->{name} cmp $b->{destination}->{name} ||
                          $a->{resolved_destination}->{name} cmp $b->{resolved_destination}->{name} ||
                          $a->{encapsulation}->cmp_str() cmp $b->{encapsulation}->cmp_str()} @filtered_formats;

foreach my $table (sort {$a->{name} cmp $b->{name}} values %Table::tables) {
    my $encodings = "";
    my $hw_configs = "";
    my @enums;
    my $header_types = "";

    my $sv_cfg = "";

    foreach my $size (qw/narrow wide protected/) {
        next if $table->{$size."_size"} == 0;

        $header_types .= $table->get_raw_header_type($size);

        $encodings .= sprintf "//  %s\n", $table->get_encoding_header($size);
        $encodings .= sprintf "//  %s\n", $table->get_encoding_line($size);
        foreach my $format (@filtered_formats) {
            next if ($format->{format} ne $size);
            next if ($format->{destination}->{table} ne $table);

            $encodings .= sprintf "//  %s\n", $format->get_encoding();

            my ($header_type, $header_type_name) = $format->get_header_type($size);

            my $header_type_enum = uc($table->{name})."_ENTRY_TYPE_".uc($header_type_name);
            push @enums, $header_type_enum;

            $header_types .= $header_type;

            # $hw_configs .= sprintf "// HWCFG: %s\n", $format->get_hw_config();
            $sv_cfg .= sprintf "  //%s\n", $table->get_encoding_line($size);
            $sv_cfg .= sprintf "  //%s\n", $format->get_encoding();
            $sv_cfg .= sprintf "  //%s\n", $table->get_encoding_line($size);
            $sv_cfg .= "  //\n";
            $sv_cfg .= "  // ".join("\n  // ", split("\n", lc($header_type)))."\n";
            $sv_cfg .= "\n";
            $sv_cfg .= "  key   = new;\n";
            $sv_cfg .= "  value = new;\n";
            $sv_cfg .= "\n";
            $sv_cfg .= "  key.type_i = NPL_$header_type_enum;\n";
            $sv_cfg .= "  value.action = NPL_".uc($table->{name})."_TYPE_DECODING_TABLE_ACTION_WRITE;\n";
            $sv_cfg .= $format->get_hw_config(lc($table->{name}));
            $sv_cfg .= "\n";

            $sv_cfg =~ s/$table$//g;
        }
        $encodings .= sprintf("//  %s\n", $table->get_encoding_line($size));

    }

    if (scalar(@enums) >= 1) {
        write_sv("// Table $table->{name}:\n");
        write_sv("//\n");
        write_sv($encodings);
        write_sv("\n");
    }

    write_sv("function void configure_".lc($table->{name})."_type_decoding_table();\n");
    write_sv("\n");
    write_sv("  npl_".lc($table->{name})."_type_decoding_table_key_c key;\n");
    write_sv("  npl_".lc($table->{name})."_type_decoding_table_value_c value;\n");
    write_sv("\n");

    if (scalar(@enums) >= 1) {
        printf OUTFILE "// Table $table->{name}:\n";
        printf OUTFILE "//\n";
        printf OUTFILE $encodings;
        printf OUTFILE "\n";
        # printf OUTFILE "// HWCFG: %s\n", Format::get_hw_title_0();
        # printf OUTFILE "// HWCFG: %s\n", Format::get_hw_title_1();
        # printf OUTFILE "// HWCFG: %s\n", Format::get_hw_title_2();
        # printf OUTFILE "// HWCFG: %s\n", Format::get_hw_title_3();
        # printf OUTFILE $hw_configs;
        # printf OUTFILE "\n";

        printf OUTFILE "enum_type %s_entry_type_e {\n", lc($table->{name});
        my $i = 0;
        my $max = max map {length($_)} @enums;
        foreach my $enum (@enums) {
            printf OUTFILE "  %-".$max."s %s\n", uc($enum), sprintf(" = $table->{type_size}'d$i;");
            $i++;
        }
        printf OUTFILE "}\n";

        printf OUTFILE lc($header_types);
        printf OUTFILE "\n";

        write_sv($sv_cfg);

        write_sv("endfunction: configure_".lc($table->{name})."_type_decoding_table\n");
        write_sv("\n");
    }
}

close OUTFILE;

open OUTFILE, ">resolution_macro_types_cfg.sv";
print OUTFILE $sv_config;
close OUTFILE;

1;

sub write_sv {
    $sv_config .= sprintf shift, shift, shift, shift, shift, shift, shift, shift;
}

sub uniq {
    my %seen;
    grep !$seen{$_->cmp_str()}++, @_;
}

sub merge() {
    my @rv = ();
    for my $i (0..3) {
        my $l = shift;
    # while (my $l = shift) {
        next if not defined($l);
        if (ref($l) eq "ARRAY") {
            foreach my $m (@{$l}) {
                push @rv, $m;
            }
        }
        else {
            push @rv, $l;
        }
    }
    return \@rv;

}

sub print_list() {
    my $r = shift;
    if (not(defined($r))) {
        printf OUTFILE "not a list(1)\n";
        return;
    }
    if (ref($r) eq "ARRAY") {
        foreach my $m (@{$r}) {
            printf OUTFILE "%s, ", $m->{name};
        }
    }
    else {
        printf OUTFILE "not a list(2)";
    }
    printf OUTFILE "\n";
}

sub add_formats() {
    my $app = shift;
    my $table = shift;
    my $start_encapsulation = shift;
    my $destination = shift;
    my $encapsulation = shift; # this is a list
    my $protected = shift;
    my $use_index = shift;

    foreach my $d (@{$destination}) {
#       if (not defined $protected) {
#            Format->new($app, $table, $start_encapsulation, $d, $encapsulation);
#        }
#        else {
#            my @e = @{$encapsulation};
#            push @e, $protected;
#            my $ref_protected = Format->new($app, $table, $start_encapsulation, $d, \@e);
#            $ref_protected->{can_protect} = 1;
#            my $ref_use_index = Format->new($app, $table, $start_encapsulation, $d, $encapsulation, $protected, $ref_protected);
#        }
        if (defined($protected)) {
            my @e = @{$encapsulation};
            push @e, $protected;

            # add a protected entry
            my $ref_protected = Format->new($app, $table, $start_encapsulation, $d, \@e);
            $ref_protected->{can_protect} = 1;

            # add a non protected entry that places the index in the encap data
            my $ref_use_index = Format->new($app, $table, $start_encapsulation, $d, $encapsulation, $protected);
        }
        elsif (defined($use_index)) {
            Format->new($app, $table, $start_encapsulation, $d, $encapsulation, $use_index);
        }
        else {
            Format->new($app, $table, $start_encapsulation, $d, $encapsulation);
        }
    }
}

package Application;

our @applications;

sub new {
    my $class = shift;

    my $self = {};
    bless $self, $class;

    $self->{name} = shift;

    push @applications, $self;

    return $self;
}

sub add_encap_data {
    my $self = shift;

    my $encap_data = shift;

    my @list;
    my $p = 80;
    foreach my $f (@{$encap_data}) {
        $p -= $f->{nbits};

        my $pad = $p & 3;
        $p &= 0xFFFC;

        if ($pad) {
            push @list, Bits->new("0"x$pad, $pad, $p + $f->{nbits});
        }

        push @list, Bits->new($f->{name}, $f->{nbits}, $p);
    }

    push @{$self->{encap_data}}, Encapsulation->new(\@list);
}

sub get_offset {
    my $self = shift;

    my $var = shift;

    foreach my $e (@{$self->{encap_data}}) {
        foreach my $v (@{$e->{list}}) {
            return $v->{start} if ($var->{name} eq $v->{name});
        }
    }

    printf OUTFILE "ERROR: can't find $var->{name} in $self->{name} encapsulation data\n";

    return "?";
}

package Table;

our %tables;

sub new {
    my $class = shift;

    my $self = {};
    bless $self, $class;

    $self->{type_size} = 0;
    $self->{narrow_size} = 0;
    $self->{wide_size} = 0;
    $self->{protected_size} = 0;

    $self->{name} = shift;
    while (my $k = shift) {
        $self->{$k} = shift;
    }

    # add to tables list
    $tables{$self->{name}} = $self;

    return $self;
}

sub get_raw_header_type {
    my $self = shift;
    my $size = shift;

    return sprintf("header_type %s%s_raw_t {\n".
                   "  fields {\n".
                   "    payload : %d;\n".
                   "    type    : %s_entry_type_e;\n".
                   "  }\n".
                   "}\n",
                   $self->{name},
                   ($size eq "narrow" && $self->{wide_size} == 0 && $self->{protected_size} == 0) ? "" : "_".$size,
                   $self->{$size."_size"} - $self->{type_size},
                   $self->{name});

}

sub get_encoding_header {
    my $self = shift;
    my $w = shift;
    my $width = $self->{$w."_size"};

    my $rv = join "", map sprintf("%16d", 8*$_), reverse(0..7);

    return " ".substr($rv, 128-2*$width, 2*$width+2);
}

sub get_encoding_line {
    my $self = shift;
    my $w = shift;
    my $width = $self->{$w."_size"};

    return " ".("+-" x $width)."+";
}


package Value;

sub new {
    my $class = shift;

    my $self = {};
    bless $self, $class;

    $self->{name} = shift;
    $self->{nbits} = shift;

    return $self;
}

package Destination;

our %destinations;

sub new {
    my $class = shift;

    my $self = {};
    bless $self, $class;

    $self->{name} = shift;
    $self->{enc} = shift;
    $self->{table} = shift;

    # some calculations
    $self->{nbits} = scalar(grep {$_ eq "-"} @{$self->{enc}});
    $self->{enc_str} = join("", @{$self->{enc}});

    $self->{can_appear_as_encoded} = 1;
    $self->{dont_narrow_if_start_encap} = 0;

    $destinations{$self->{name}} = $self;

    return $self;
}

sub get_cfg_nbits {
    my $self = shift;
    return scalar(grep {$_ eq "-"} @{$self->{enc}});
}

sub get_5b_prefix {
    my $self = shift;
    my $rv = substr(join("", @{$self->{enc}}),0,5);
    $rv =~ s/x/0/g;
    $rv =~ s/-/0/g;
    return $rv;
}

package Encapsulation;

sub new {
    my $class = shift;

    my $self = {};
    bless $self, $class;

    $self->{list} = shift;

    return $self;
}

sub get_str {
    my $self = shift;

    return join ", ", map(sprintf($_->{name}."(".$_->{nbits}.")"), @{$self->{list}});
}

sub cmp_str {
    my $self = shift;

    return join ",", sort map $_->{name}, @{$self->{list}};
}

sub get_size {
    my $self = shift;

    return eval join "+", map $_->{nbits}, @{$self->{list}};
}

sub contains {
    my $self = shift;
    my $d = shift;

    foreach my $e (@{$self->{list}}) {
        return 1 if ($e == $d);
    }
    return 0;
}


package Bits;

sub new {
    my $class = shift;
    my $self = {};
    bless $self, $class;

    $self->{name} = shift;
    $self->{width} = shift;
    $self->{start} = shift;

    $self->{nbits} = $self->{width};

    return $self;
}

sub get_str {
    my $self = shift;

    my $width_in_bits = 2*$self->{width} - 1;

    my $name = $self->{name}."(".$self->{width}.")";

    $name = (length($name) > $width_in_bits) ? substr($name, 0, $width_in_bits) : $name;

    my $pad_pre = int(($width_in_bits - length($name))/2);
    my $pad_post = $width_in_bits - $pad_pre - length($name);

    return (" "x$pad_pre).$name.(" "x$pad_post);

    # return $self->{name}."(".$self->{width}.",".$self->{start}.")";
}

package Format;

our @formats;
our %header_type_names;

sub new {
    my $class = shift;

    my $self = {};
    bless $self, $class;

    $self->{app}                  = [shift];
    my $d = shift;
    $self->{destination}          = $Destination::destinations{$d};
    $self->{start_encapsulation}  = shift;
    $self->{resolved_destination} = shift;
    $self->{encapsulation}        = Encapsulation->new(shift);
    $self->{use_index}            = shift;
    $self->{protected_by}         = shift;

    push @formats, $self;

    return $self;
}

sub calc_size {
    my $self = shift;

    my $t = $self->{destination}->{table};

    my $size_str = "";

    $self->{size} = $self->{destination}->{table}->{type_size};
    $size_str .= "type($self->{destination}->{table}->{type_size}) + ";

    if ($self->{start_encapsulation} && (scalar(@{$self->{app}}) > 1)) {
    $self->{size} += 4 ;
    $size_str .= "enc_type(4) + ";
    }

    if ($self->{encapsulation}->contains($self->{resolved_destination}) == 0) {
        $self->{size} += $self->{resolved_destination}->{nbits};
    $size_str .= "resolved_destination($self->{resolved_destination}->{nbits}) + ";
    }

    $self->{size} += $self->{encapsulation}->get_size();
    $size_str .= sprintf("encapsulation(%d) = $self->{size}", $self->{encapsulation}->get_size());

#   printf "  $size_str\n";
}

sub calc_format {
    my $self = shift;

    $self->calc_size();

#   print "self keys = ", join(" ",keys %{$self}), "\n";
#   printf "self->{app}(%s) = ", (scalar(@{$self->{app}}));
#   for my $app ( @{$self->{app}} ) {
#      print $app->{name}, ", ";
#   }
#   print "\n";
#   print "self->{destination} = ", $self->{destination}->{name}, "\n"; # me as a destination
#   print "self->{destination}->{table} = ", $self->{destination}->{table}->{name}, "\n"; # the table that resolves me as a destination
#   print "self->{resolved_destination} = ", $self->{resolved_destination}->{name}, "\n"; # the next destination after me
#   print "self->{size} = ", $self->{size}, "\n";
#   print "self->{start_encapsulation} = ", $self->{start_encapsulation}, "\n";


    my $format = "?";
    $format = "wide" if ($self->{size} <= $self->{destination}->{table}->{wide_size});
    $format = "narrow" if (($self->{size} <= $self->{destination}->{table}->{narrow_size}) && ($self->{resolved_destination}->{dont_narrow_if_start_encap}==0)); # || $self->{start_encapsulation} eq "")

    $format = "protected" if ($self->{can_protect}) && ($self->{size} <= $self->{destination}->{table}->{protected_size});

    $self->{format} = $format; # substr($format, 0, 1);
#   print "self->{format} = ", $self->{format}, "\n";

    # expand destination to 20 if possible
    ## printf("trying to expand destination for %s\n", $self->cmp_str());
    if ($self->{encapsulation}->contains($self->{resolved_destination}) == 0) {
    ## printf("  trying: table_size-my_size >= 20-destination_size : %d - %d >= 20 - %d\n",
        ##        $self->{destination}->{table}->{$format."_size"}, $self->{size}, $self->{resolved_destination}->{nbits});

#   print "self->{resolved_destination}->{can_appear_as_encoded} = ", $self->{resolved_destination}->{can_appear_as_encoded}, "\n";
    if (($self->{resolved_destination}->{can_appear_as_encoded}) &&
        ($self->{destination}->{table}->{$format."_size"}-$self->{size} >= 20-$self->{resolved_destination}->{nbits}) ) {
#       if ($self->{destination}->{table}->{$format."_size"}-$self->{size} >= 20-$self->{resolved_destination}->{nbits}) {
        ## printf("  expanding\n");
            push @{$self->{destinations}}, $self->{resolved_destination};
            $self->{size} = $self->{size} + 20 - $self->{resolved_destination}->{nbits};
            $self->{resolved_destination} = $full_destination;
        }
    }

#   print "self->{destinations} ";
#   for my $resolved_dest ( @{$self->{destinations}} ) {
#      print $resolved_dest->{name}, ", ";
#   }
#   print "\n";
#   print "self->{destinations}", @{$self->{destinations}}[1]->{name}, "\n";



    if ($format ne "?") {
    if ($self->{start_encapsulation} ne "") {
        # add encapsulation type if more than one application
        if (scalar(@{$self->{app}}) > 1) {
        unshift @{$self->{encoding}}, Bits->new("enc_type", 4, $self->{destination}->{table}->{$format."_size"} - 4);
        $self->{start_encapsulation} = "cfg";
        }
        # add encapsulation type if there are enough bits and one field
        if (scalar(@{$self->{encapsulation}->{list}}) <= 1) {
        if ($self->{destination}->{table}->{$format."_size"} - $self->{size} >= 4) {
            unshift @{$self->{encoding}}, Bits->new("enc_type", 4, $self->{destination}->{table}->{$format."_size"} - 4);
            $self->{size} += 4;
            $self->{start_encapsulation} = "cfg";
        }
        }
    }
        my $position = 0;
        unshift @{$self->{encoding}}, Bits->new("type", $self->{destination}->{table}->{type_size}, $position);
        $position += $self->{destination}->{table}->{type_size};

        unshift @{$self->{encoding}}, Bits->new($self->{resolved_destination}->{name}, $self->{resolved_destination}->{nbits}, $position);
        $position += $self->{resolved_destination}->{nbits};

        foreach my $e (@{$self->{encapsulation}->{list}}) {
            next if ($e eq $self->{resolved_destination});
            unshift @{$self->{encoding}}, Bits->new($e->{name}, $e->{nbits}, $position);
            $position += $e->{nbits};
        }

        my $padding = $self->{destination}->{table}->{$format."_size"} - $self->{size};
        if ($padding > 0) {
            unshift@{$self->{encoding}}, Bits->new("padding", $padding, $position);
        }

    }
}

sub add_app {
    my $self = shift;

    my $new_app = shift;
    my $found = 0;
    foreach my $app (@{$self->{app}}) {
        $found = 1 if $app eq $new_app;
    }

    push @{$self->{app}}, $new_app unless $found;
}

sub add_destination {
    my $self = shift;

    my $new_dest = shift;
    my $found = 0;
    foreach my $dest (@{$self->{destinations}}) {
        $found = 1 if $dest eq $new_dest;
    }

    push @{$self->{destinations}}, $new_dest unless $found;
}

# this function is used both as a class-method and as an object-method
sub get_str {
    my $self = shift;

#   my $is_data_row = shift // 1;
    my $is_header_row = shift // 0;
#   $print_header = shift if @_;
#   print "print_header = ", $print_header, "\n";

#       print "*****self->get_app_names_str() *", $self->get_app_names_str(), "*\n";
#   print "*****self->{size} *", $self->{size}, "*\n";
#   print "*****substr(self->{format}, 0, 1) *", substr($self->{format}, 0, 1), "*\n";
#   print "*****self->cmp_str() *", $self->cmp_str(), "*\n";
#   print "*****self->get_destination_names_str() *", $self->get_destination_names_str(), "*\n";   //TODO - igors remove

    return sprintf("%-26s %-4s %-5s %-150s %-s",
                   $is_header_row? "App_names"           : $self->get_app_names_str(),
                   $is_header_row? "Size"                : $self->{size},
                   $is_header_row? "n/w/p"               : substr($self->{format}, 0, 1),
                                                           $self->cmp_str($is_header_row),
                   $is_header_row? "Destination_names"   : $self->get_destination_names_str() );
}


sub get_hw_title_0 {
    return "Destination Encapsulation  Index      Field-0          Field-1";
}
sub get_hw_title_1 {
    return "size+mask   start          size+dest  offset+size+dest offset+size+dest";
}
sub get_hw_title_2 {
    return "              add_enc_type";
}
sub get_hw_title_3 {
    return "                enc_type";
}
sub get_hw_config {
    my $self = shift;
    my $table = shift;

    my $rv = "";

    # Next-Destination
    # $rv .= sprintf("%2s, %5s   ",
    #                $self->{resolved_destination}->get_cfg_nbits(),
    #                $self->{resolved_destination}->get_5b_prefix());

    $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.next_destination_size          = 5'd%d;\n", $table, $self->{resolved_destination}->get_cfg_nbits());
    $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.next_destination_mask          = 5'b%s;\n", $table, $self->{resolved_destination}->get_5b_prefix());

    # Encapsulation
    my $add_enc_type = ($self->{start_encapsulation} ne "") && ($self->{start_encapsulation} ne "cfg"); # && (scalar(@{$self->{app}}) == 1);

    # $rv .= sprintf("%d %d %4s       ",
    #                $self->{start_encapsulation},
    #                $add_enc_type,
    #                $add_enc_type ? substr(${$self->{app}}[0]->{name},0,4) : "0000");

    $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.encapsulation_start            = 1'b%d;\n", $table, $self->{start_encapsulation} eq "" ? 0 : 1);
    $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.encapsulation_add_type         = 1'b%d;\n", $table, $add_enc_type);
    $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.encapsulation_type             = %s;\n",    $table, ($add_enc_type ? "NPL_".$self->{start_encapsulation} : "\$random"));

    # Index: Size-in-nibbles, Destination-in-nibbles
    # todo: check position in all applications
    if ($self->{use_index}) {
        my $destination = ${$self->{app}}[0]->get_offset($self->{use_index});
        sprintf("ERROR destinatoin is not in nibbles\n") if ($destination & 0x3);
        # $rv .= sprintf("1 %2d       ", ${$self->{app}}[0]->get_offset($self->{use_index}));
        $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.index_size_in_nibbles          = 3'd%d;\n", $table, (3+$self->{use_index}->{nbits})/4);
        $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.index_destination_in_nibbles   = 5'd%d;\n", $table, (($destination) / 4));
    }
    else {
        # $rv .= sprintf("0 0        ");
        $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.index_size_in_nibbles          = 3'd0;\n",    $table);
        $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.index_destination_in_nibbles   = \$random;\n", $table);
    }

    # my @name = reverse grep {$_ ne "type" && $_ ne "enc_type" && $_ ne "padding"} map($_->{name}, );

    my @l;
    foreach my $e (reverse @{$self->{encoding}}) {
        next if $e->{name} eq "type";
        next if $e->{name} eq "padding";
        if ($e->{name} eq $self->{resolved_destination}->{name}) {
            next if ($self->{encapsulation}->contains($self->{resolved_destination}) == 0);
        }
        my $en = {name   => $e->{name},
                  start  => $e->{start},
                  width  => $e->{width},
                  offset => ${$self->{app}}[0]->get_offset($e)};
        push @l, $en;
    }

    foreach my $i (0..scalar(@l)-2) {
        if ( (@l[0]->{start}  + @l[0]->{width} == @l[1]->{start}) &&
             (@l[0]->{offset} + @l[0]->{width} == @l[1]->{offset}) &&
             (@l[0]->{width} + @l[1]->{width} < 32)                  ) {
            $l[1]->{start} = $l[0]->{start};
            $l[1]->{offset} = $l[0]->{offset};
            $l[1]->{width} += $l[0]->{width};
            shift @l;
        }
    }

    if ($#l > 1) {
      $rv .= "\nERROR: too many fields\n";
      printf "ERROR: too many fields";
    }

    foreach my $i (0..1) {
      if ($i <= $#l) {
    my $e = $l[$i];

        if ($e->{width} > 31) {
            $rv .= "\nERROR: wide field\n";
            printf "ERROR: wide field";
        }

        # Field-?: Offset-in-bits, Size-in-bits, Destination-in-nibbles
        # $rv .= sprintf("%2d %2d %2d         ",
        #                $e->{start},
        #                $e->{width},
        #                $e->{offset});
    printf("ERROR: offset not in nibbles\n") if ($e->{offset} & 3);

    $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.field_$i.offset_in_bits         = 6'd%d;\n", $table, $e->{start});
        $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.field_$i.size_in_bits           = 5'd%d;\n", $table, $e->{width});
        $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.field_$i.destination_in_nibbles = 5'd%d;\n", $table, $e->{offset}/4);
        $i++;
      }
      else {
    $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.field_$i.offset_in_bits         = \$random;\n", $table);
        $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.field_$i.size_in_bits           = 5'd0;\n", $table);
        $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.field_$i.destination_in_nibbles = \$random;\n", $table);
      }
    }

    $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.lb_key_overwrite               = 1'b0;\n",     $table);
    $rv .= sprintf("  value.payloads.%s_type_decoding_table_result.lb_key_offset                  = \$random;\n", $table);

    # $rv .= sprintf("  table_conf.add_header_comment(\$sformatf(\"TABLE: %s_type_decoding_table FROM: \%s\", this.get_name()));\n", $table);
    $rv .= sprintf("  config_%s_type_decoding_table(key, value, table_conf);\n", $table);

    return $rv;
}

sub get_encoding {
    my $self = shift;

    my $rv = "";

    $rv .= " |";

    $rv .= $self->get_entry_format_str();

    $rv .= $self->{start_encapsulation} ? " E" : "  ";
    $rv .= $self->{use_index} ? " i" : "  ";

    $rv .= " " . $self->get_app_names_str();

    if (defined($self->{destinations}) && (scalar(@{$self->{destinations}} > 1))) {
        $rv .= sprintf("; destination: %s", $self->get_destination_names_str());
    }

    return $rv;
}

sub get_app_names_str {
    my $self = shift;

    my $rv = join("|", map {$_->{name}} @{$self->{app}});

    return $rv;
}

sub get_destination_names_str {
    my $self = shift;

    my $rv = join("|", map {$_->{name}} @{$self->{destinations}});

    return $rv;
}

sub get_entry_format_str {
    my $self = shift;

    my $rv = "";

    foreach my $encoding (sort {$b->{start} <=> $a->{start}} grep { defined } @{$self->{encoding}}) {
        $rv .= sprintf("%s|", $encoding->get_str());
    }

    return $rv;
}

sub get_header_type_name {
    my $self = shift;

    if (not(defined($self->{header_type_name}))) {

        # get all fields that are not type, enc_type or padding
        my @name = reverse grep {$_ ne "type" && $_ ne "enc_type" && $_ ne "padding"} map($_->{name}, @{$self->{encoding}});

        $self->{header_type_name} = $self->{destination}->{table}->{name}."_".(join("_", @name));

        my $i = 1;
        while (defined($header_type_names{$self->{header_type_name}})) {
            $self->{header_type_name} = $self->{destination}->{table}->{name}."_".(join("_", @name)).$i;
            $i++;
        }
        $header_type_names{$self->{header_type_name}} = 1;
    }

    return $self->{header_type_name};

}

sub get_header_type {
    my $self = shift;
    my $size = shift;

    my $rv = "";

    my $header_type_name = $self->get_header_type_name();

    $rv .= sprintf("header_type %s_t {\n", $header_type_name);
    $rv .= "  fields {\n";

    my $max = 0;
    foreach my $encoding (@{$self->{encoding}}) {
        $max = length($encoding->{name}) if $max < length($encoding->{name});
    }

    foreach my $encoding (sort {$b->{start} <=> $a->{start}} @{$self->{encoding}}) {
        my $nbits = $encoding->{width};
        $nbits = sprintf("%s_entry_type_e", $self->{destination}->{table}->{name}) if $encoding->{name} eq "type";
        $rv .= sprintf("    %-".$max."s : $nbits;", $encoding->{name});

        # if ( ($encoding->{name} eq "destination") && defined($self->{destinations}) && (scalar(@{$self->{destinations}} > 1))) {
        if (lc($encoding->{name}) eq "destination") {
            $rv .= sprintf(" // may be: %s", join(" or ", map($_->{name}, @{$self->{destinations}})));
        }

        $rv .= "\n";
    }

    $rv .= "  }\n";
    $rv .= "}\n";
    return ($rv, $header_type_name);
}

# this function is used both as a class-method and as an object-method
sub cmp_str {
    my $self = shift;

    my $is_header_row = shift // 0;
#   my $is_data_row = shift // 1;
#   my $is_header_row = not $is_data_row;

    my $rv = sprintf("%-20s %-20s %-55s %-20s %-50s",
                     $is_header_row? "Destination"       : $self->{destination}->{name},
                     $is_header_row? "Next_dest"         : $self->{resolved_destination}->{name}."(".$self->{resolved_destination}->{nbits}.")",
                     $is_header_row? "Encap_info"        : "[".$self->{encapsulation}->get_str()."]",
                     $is_header_row? "Use_index"         : (defined $self->{use_index} ? $self->{use_index}->{name}."(".$self->{use_index}->{nbits}.")" : ""),
                     $is_header_row? "Start_encap_type"  : $self->{start_encapsulation});

    return $rv;
}

