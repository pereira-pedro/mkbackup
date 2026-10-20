# Shared by the managed job; accepts legacy mmm/DD/YYYY and ISO YYYY-MM-DD dates.
# YYYYMMDDHHIISS uses the router's existing local timezone; II means minutes.
:local formatTimestamp do={
    :local dateText $1
    :local timeText $2
    :local year ""
    :local month ""
    :local day ""
    :if (([:len $dateText] = 11) && ([:pick $dateText 3 4] = "/") && ([:pick $dateText 6 7] = "/")) do={
        :local months {"jan"="01";"feb"="02";"mar"="03";"apr"="04";"may"="05";"jun"="06";"jul"="07";"aug"="08";"sep"="09";"oct"="10";"nov"="11";"dec"="12"}
        :set year [:pick $dateText 7 11]
        :set month ($months->[:pick $dateText 0 3])
        :set day [:pick $dateText 4 6]
    } else={
        :if (([:len $dateText] != 10) || ([:pick $dateText 4 5] != "-") || ([:pick $dateText 7 8] != "-")) do={ :error "mkbackup: unsupported clock date format" }
        :set year [:pick $dateText 0 4]
        :set month [:pick $dateText 5 7]
        :set day [:pick $dateText 8 10]
    }
    :if (([:len $timeText] != 8) || ([:pick $timeText 2 3] != ":") || ([:pick $timeText 5 6] != ":")) do={ :error "mkbackup: unsupported clock time format" }
    :local hour [:pick $timeText 0 2]
    :local minute [:pick $timeText 3 5]
    :local second [:pick $timeText 6 8]
    :local stamp ($year . $month . $day . $hour . $minute . $second)
    :if (([:len $stamp] != 14) || !($stamp ~ "^[0-9]+\$")) do={ :error "mkbackup: invalid clock timestamp" }
    :local yearNumber [:tonum $year]
    :local monthNumber [:tonum $month]
    :local dayNumber [:tonum $day]
    :if (($yearNumber < 2000) || ($monthNumber < 1) || ($monthNumber > 12) || ($dayNumber < 1) || ([:tonum $hour] > 23) || ([:tonum $minute] > 59) || ([:tonum $second] > 59)) do={ :error "mkbackup: invalid clock; correct date/time before exporting" }
    :local days 31
    :if (($monthNumber = 4) || ($monthNumber = 6) || ($monthNumber = 9) || ($monthNumber = 11)) do={ :set days 30 }
    :if ($monthNumber = 2) do={
        :set days 28
        :if ((($yearNumber % 4) = 0) && ((($yearNumber % 100) != 0) || (($yearNumber % 400) = 0))) do={ :set days 29 }
    }
    :if ($dayNumber > $days) do={ :error "mkbackup: invalid calendar date" }
    :return $stamp
}
