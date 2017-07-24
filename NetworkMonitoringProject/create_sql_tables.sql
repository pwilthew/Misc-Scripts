DROP TABLE IF EXISTS devices, found_devices;

CREATE TABLE devices (
                      if_index INT(5) NOT NULL KEY,
                      mac VARCHAR(50), 
                      name VARCHAR(120), 
                      management_ip VARCHAR(50), 
                      up_link_ports VARCHAR(50)
                      );

CREATE TABLE found_devices (
                            if_index INT(5) NOT NULL KEY,
                            mac VARCHAR(50), 
                            vlan VARCHAR(5),
                            staff_name VARCHAR(120),
                            switch_port INT(5), 
                            make_model VARCHAR(120),
                            description VARCHAR(120),
                            first_detection VARCHAR(15),
                            most_recent_detection VARCHAR(5),
                            allowed_vlan_list VARCHAR(120),
                            most_recent_ipv4 VARCHAR(50),
                            most_recent_ipv6 VARCHAR(50)
                            );


