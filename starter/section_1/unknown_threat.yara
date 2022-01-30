rule command_control_server {
        meta:
                Author = "@pavloteyfel"
                Description = "detecs malicious scripts associated to the darkl0rd domain activity"
        strings:
                $domain = "darkl0rd.com"
        condition:
                $domain
}
