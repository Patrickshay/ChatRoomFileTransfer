#include <stdio.h>

// forward declarations
void start_server();
void start_client();

int main() {
    int choice;
    while (1) {
        printf("1 = Server   2 = Client > ");
        fflush(stdout);

        if (scanf("%d", &choice) != 1) {
            // non‐integer input: clear stdin and retry
            while (getchar() != '\n');
            fprintf(stderr, "[Error] Please enter 1 or 2.\n");
            continue;
        }
        // clear any trailing newline
        while (getchar() != '\n');

        if (choice == 1) {
            start_server();
            break;
        }
        else if (choice == 2) {
            start_client();
            break;
        }
        else {
            fprintf(stderr, "[Error] Invalid selection. Enter 1 for Server or 2 for Client.\n");
        }
    }
    return 0;
}
