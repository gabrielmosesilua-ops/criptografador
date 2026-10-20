# criptografador

Aplicação de criptografia de mensagens em HTML/JavaScript, compatível com GitHub Pages.

Como funciona
- A senha nunca é enviada para nenhum servidor.
- A chave é derivada com PBKDF2-HMAC-SHA256 usando um salt aleatório.
- O texto é cifrado com AES-GCM no navegador.
- O resultado é salvo em formato seguro, com salt + IV + texto cifrado em base64url.

Como usar
1. Abra a página em um navegador.
2. Digite a senha e a mensagem.
3. Clique em "Criptografar".
4. Para recuperar, cole o texto no campo de decifração e use a mesma senha.

Observação
- O backend em Python (`app.py`) continua presente como utilitário local opcional, mas a versão que funciona no GitHub Pages usa criptografia no navegador, sem servidor.

Hospedagem
- GitHub Pages: basta publicar este repositório como site estático.
- Local: você também pode abrir `index.html` diretamente em um navegador ou rodar o servidor Python opcional com `python app.py`.
