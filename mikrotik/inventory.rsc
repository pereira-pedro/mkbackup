# Read-only inventory. Do not export sensitive configuration or SSH debug logs.
/system/resource/print
/system/routerboard/print
/system/identity/print
/system/clock/print
# Do not print script sources/on-event bodies: old scripts may contain passwords.
:foreach item in=[/system/scheduler/find] do={
    :put ("schedule=" . [/system/scheduler/get $item name] . " owner=" . [/system/scheduler/get $item owner] . " interval=" . [/system/scheduler/get $item interval])
}
:foreach item in=[/system/script/find] do={
    :put ("script=" . [/system/script/get $item name] . " owner=" . [/system/script/get $item owner] . " policy=" . [/system/script/get $item policy])
}
/user/ssh-keys/private/print
/ip/ssh/print
# If supported, inspect without changing:
# /ip/ssh/known-hosts/print
# Record the backup job owner, file sizes, egress public IP and upgrade window.
