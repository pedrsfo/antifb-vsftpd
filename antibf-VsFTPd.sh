#!/bin/bash

# Nome do script: antibf-VsFTPd.sh
# Autor: Pedro Otávio
# Atualização: 11/02/2022

# Este script tem por finaidade conter ataques de força bruta em servidores VsFTPd.
# Este script funciona monitorando os logs contidos em /var/log/vsftpd.log e verificando o número de tentativas falhas
# de um determinado endereço IP em um periodo de tempo. Caso ocorra 5 tentativas de um único IP em apenas 1 minuto,
# é então considerado um ataque de força bruta no sistema. Após a detecção é criada uma regra no firewall bloqueando o
# atacante.

# Para melhor compreensão do script a segui, recomendo o aprendizado das ferramentas CUT e SED. Além da compreenção basica
# de Expressões Regulares (REGEX).


# torna o script contínuo
while true;
do
	# coleta somente cinco linhas contendo FAIL LOGI	| coleta e filtra os campos de data hora ano e endereço ip  | unifica e adiciona no arquivo fbftp
	cat /var/log/vsftpd.log | grep "FAIL LOGIN" | tail -n 5 | cut -d " " -f 4,5,6,12 | sed 's/"::ffff://' | sed 's/ \[pid//'| sed 's/"//' | sort -u > arquivo

	# retira o campo dos segundos e quantifica as linhas, caso o valor seja igual a um  E    A data do ataque for igual a data atual
	if [ "$(cat arquivo | sed -r 's/(.{6})(...)()/\1\3/' | uniq | wc -l)" == "1" ] && [ "$(date +%H:%M:%Y | sed -r 's/(.{5})(:)(.{4})/\1 \3/')" == "$(tail -n 1 arquivo | cut -d " " -f 1,2 | sed -r 's/(.{5})(:..)(.{5})/\1\3/')" ];
	then
		# Notifique o adm do sistema aqui (Insira o comando desejado).
		echo -e " ATAQUE DE FORÇA BRUTRA DETECTADO!!!"

		# Filtra o endereço IP do atacante e adciona em uma variável.
		ip=$(cat arquivo | cut -d " " -f 3)

		echo -e "\n IP do atacante: $ip"

		# bloqueie o endereço IP do atacante
		iptables -A INPUT -s $ip -j DROP

		# aguarda a o minuto acabar
		sleep 58

	else
		echo "Tudo normal"

	fi

	# Apaga o arquivo temporário
	rm arquivo

	# Verifica a cada 2 segundos
	sleep 2
done
;
