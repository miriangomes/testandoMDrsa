#include "backendRSA.c"
#include <stdbool.h>

#define MAX_SIZE 2048

void limparBuffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) {}
}

int main(int argc, char const *argv[]) {
    printf("==============================================================\n");
    printf("====  RSA Protocol backend test using Emscripten and GMP  ====\n");
    printf("==============================================================\n");

    short operacao;

    while (true) {
        printf("\n");
        printf("************ Qual operação que você irá realizar? ************\n");
        printf("\n");
        printf("[1] Gerar chave pública\n");
        printf("[2] Criptografar mensagem\n");
        printf("[3] Descriptografar mensagem\n");
        printf("[0] Encerrar execução\n");
        printf("\n");
        printf("Digite a operação desejada: ");
        scanf("%hd", &operacao);
        limparBuffer();
        printf("\n");

        if (operacao == 0) {
            return 0;

        } else if (operacao == 1) {
            char p[MAX_SIZE], q[MAX_SIZE], e[MAX_SIZE];
            printf("Digite o valor de p: ");
            scanf("%s", p);
            printf("Digite o valor de q: ");
            scanf("%s", q);
            printf("Digite o valor de e: ");
            scanf("%s", e);
            limparBuffer();

            const char *public_key = generatePublicKey(p, q, e);
            printf("Chave pública gerada: (%s, %s)\n", public_key, e);

        } else if (operacao == 2) {
            char n[MAX_SIZE], e[MAX_SIZE];
            printf("Informe a chave pública (n, e): ");
            scanf("%s %s", n, e);
            limparBuffer();

            printf("Digite a mensagem a ser criptografada: ");
            char msg[MAX_SIZE];
            fgets(msg, MAX_SIZE, stdin);
            msg[strcspn(msg, "\n")] = '\0'; // Remove a quebra de linha

            const char *cypher = encryptMessage(msg, n, e);
            printf("Mensagem criptografada:\n%s\n", cypher);

        } else if (operacao == 3) {
            char p[MAX_SIZE], q[MAX_SIZE], e[MAX_SIZE];
            printf("Informe a chave privada (p, q, e): ");
            scanf("%s %s %s", p, q, e);
            limparBuffer();

            printf("Digite a mensagem criptografada: ");
            char cypher[MAX_SIZE * 10]; // Espaço para vários números criptografados
            fgets(cypher, MAX_SIZE * 10, stdin);
            cypher[strcspn(cypher, "\n")] = '\0'; // Remove a quebra de linha

            const char *decrypted = decryptMessage(cypher, p, q, e);
            printf("Mensagem decifrada:\n%s\n", decrypted);
        }
    }
}