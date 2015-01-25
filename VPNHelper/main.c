#include "vpn.h"
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

void
usage(char *name)
{
    fprintf(stderr, "usage: %s (create|edit|delete) <args>\n\
    create -n name -a address -u username -p password -s secret\n\
    edit   -i serviceid [-n name] [-a address] [-u username]\n\
                        [-p password] [-s secret]\n\
    delete -i serviceid\n", name);
}

int
main(int argc, char *argv[])
{
    char *program_name = argv[0];
    
    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root!\n");
        return 1;
    }
    
    CFStringRef service_id = NULL;
    CFStringRef service_name = NULL;
    CFStringRef server_address = NULL;
    CFStringRef username = NULL;
    CFStringRef password = NULL;
    CFStringRef shared_secret = NULL;
    
    const struct option long_options[] = {
        {"service-id",       required_argument, NULL, 'i'},
        {"service-name",     required_argument, NULL, 'n'},
        {"server-address",   required_argument, NULL, 'a'},
        {"username",         required_argument, NULL, 'u'},
        {"password",         required_argument, NULL, 'p'},
        {"shared-secret",    required_argument, NULL, 's'},
        {NULL,               no_argument,       NULL, 0  }
    };
    
    int opt;
    int opt_index = 0;
    while ((opt = getopt_long(argc, argv, "i:n:a:u:p:s:", long_options, &opt_index)) != -1) {
        switch (opt) {
            case 'i':
                service_id = CFStringCreateWithCString(NULL, optarg, kCFStringEncodingUTF8);
                break;
            case 'n':
                service_name = CFStringCreateWithCString(NULL, optarg, kCFStringEncodingUTF8);
                break;
            case 'a':
                server_address = CFStringCreateWithCString(NULL, optarg, kCFStringEncodingUTF8);
                break;
            case 'u':
                username = CFStringCreateWithCString(NULL, optarg, kCFStringEncodingUTF8);
                break;
            case 'p':
                password = CFStringCreateWithCString(NULL, optarg, kCFStringEncodingUTF8);
                break;
            case 's':
                shared_secret = CFStringCreateWithCString(NULL, optarg, kCFStringEncodingUTF8);
                break;
            case '?':
            default:
                usage(program_name);
                return 1;
        }
    }
    argc -= optind;
    argv += optind;
    
    if (argc != 1) {
        usage(program_name);
        return 1;
    }
    
    char *mode_str = argv[argc-1];
    if (strcmp(mode_str, "create") == 0) {
        int err = 0;
        
        if (service_id != NULL) {
            fprintf(stderr, "Cannot specify VPN service ID (-i)\n");
            err = 1;
        }
        
        if (service_name == NULL) {
            fprintf(stderr, "Must specify VPN name (-n)\n");
            err = 1;
        }
        
        if (server_address == NULL) {
            fprintf(stderr, "Must specify server address (-a)\n");
            err = 1;
        }
        
        if (username == NULL) {
            fprintf(stderr, "Must specify username (-u)\n");
            err = 1;
        }
        
        if (password == NULL) {
            fprintf(stderr, "Must specify password (-p)\n");
            err = 1;
        }
        
        if (shared_secret == NULL) {
            fprintf(stderr, "Must specify shared secret (-s)\n");
            err = 1;
        }
        
        if (!err) {
            L2TPConfig config = {
                .service_name = service_name,
                .server_address = server_address,
                .username = username,
                .password = password,
                .shared_secret = shared_secret,
                .send_all_traffic = kCFBooleanTrue
            };
            
            if (create_vpn(&service_id, &config)) {
                printf("Everything went okay!\n");
                printf("Service ID: %s\n", CFStringGetCStringPtr(service_id, kCFStringEncodingUTF8));
                err = 0;
            } else {
                fprintf(stderr, "Something went wrong!\n");
                err = 1;
            }
        }
        
        return err;
    } else if (strcmp(mode_str, "edit") == 0) {
        int err = 0;
        
        if (service_id == NULL) {
            fprintf(stderr, "Must specify VPN service ID (-i)\n");
            err = 1;
        }
        
        if (!err) {
            L2TPConfig config = {
                .service_name = service_name,
                .server_address = server_address,
                .username = username,
                .password = password,
                .shared_secret = shared_secret,
                .send_all_traffic = NULL
            };
            
            if (create_vpn(&service_id, &config)) {
                printf("Everything went okay!\n");
                err = 0;
            } else {
                fprintf(stderr, "Something went wrong!\n");
                err = 1;
            }
        }
        
        return err;
    } else if (strcmp(mode_str, "delete") == 0) {
        int err = 0;
        
        if (service_id == NULL) {
            fprintf(stderr, "Must specify VPN service ID (-i)\n");
            err = 1;
        }
        
        if (service_name != NULL) {
            fprintf(stderr, "Cannot specify VPN name (-n)\n");
            err = 1;
        }
        
        if (server_address != NULL) {
            fprintf(stderr, "Cannot specify server address (-a)\n");
            err = 1;
        }
        
        if (username != NULL) {
            fprintf(stderr, "Cannot specify username (-u)\n");
            err = 1;
        }
        
        if (password != NULL) {
            fprintf(stderr, "Cannot specify password (-p)\n");
            err = 1;
        }
        
        if (shared_secret != NULL) {
            fprintf(stderr, "Cannot specify shared secret (-s)\n");
            err = 1;
        }
        
        if (!err) {
            if (delete_vpn(service_id)) {
                printf("Everything went okay!\n");
                err = 0;
            } else {
                fprintf(stderr, "Something went wrong!\n");
                err = 1;
            }
        }
        
        return err;
    } else {
        usage(program_name);
        return 1;
    }
    
    return 0;
}
