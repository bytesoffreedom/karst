//! UI localization. The interface is the ONE place non-English text is allowed
//! (everything else in the code is English). Strings are keyed; `t(lang, key)`
//! returns the translation. The table is column-per-language, one row per key —
//! adding a string means adding a row with its translations inline.
//!
//! Language order in every row MUST match `Lang::idx()`. A test pins that
//! `Lang::ALL` covers the enum and that `native_name`/`code` line up.
//!
//! Arabic is intentionally NOT included yet: egui 0.29 has no complex-script
//! shaping (letters would not join and RTL would not mirror), so it would render
//! genuinely broken. The scaffold is ready to add it once a shaping engine is
//! available offline.

/// Supported UI languages. `idx()` (= `as usize`) is the column order used by every
/// translation row — do NOT reorder without updating all rows.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Lang {
    #[default]
    En,
    Zh,
    Es,
    Pt,
    Id,
    Fr,
    Ja,
    Ru,
    De,
}

impl Lang {
    /// All languages, in switcher/display order (matches column order).
    pub const ALL: [Lang; 9] =
        [Lang::En, Lang::Zh, Lang::Es, Lang::Pt, Lang::Id, Lang::Fr, Lang::Ja, Lang::Ru, Lang::De];

    /// Column index into a translation row.
    pub fn idx(self) -> usize {
        self as usize
    }

    /// Stable short code, persisted to disk and used to restore the preference.
    pub fn code(self) -> &'static str {
        ["en", "zh", "es", "pt", "id", "fr", "ja", "ru", "de"][self.idx()]
    }

    /// Endonym shown in the language switcher (each in its own script).
    pub fn native_name(self) -> &'static str {
        ["English", "中文", "Español", "Português", "Bahasa", "Français", "日本語", "Русский", "Deutsch"]
            [self.idx()]
    }

    /// Parse a persisted code back to a language (unknown -> `None`).
    pub fn from_code(s: &str) -> Option<Lang> {
        Lang::ALL.into_iter().find(|l| l.code() == s)
    }
}

/// UI string keys. One variant per translatable string.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    UnlockSubtitle,
    WelcomeSubtitleNew,
    WelcomeSubtitleAdd,
    WelcomeAddTitle,
    WelcomeAddNote,
    WelcomeNewTitle,
    WelcomeNewNote,
    BtnCreateAccount,
    BtnRestorePhrase,
    BtnCancel,
    BtnLogin,
    LinkOtherAccount,
    FieldPassword,
    NetRelay,
    NetRelayId,
    NetRelayIdHint,
    NetSocks5,
    NetSocks5Hint,
    NetRoutes,
    NetRoutesHint,
    NetExtraRelays,
    NetExtraRelaysHint,
    NetSection,
    LangLabel,
    // --- Onboarding: create-show / confirm / restore ---
    OnbSubtitleWrite,
    OnbSubtitleVerify,
    OnbSubtitleRestore,
    RecoveryPhraseTitle,
    RecoveryPhraseWarn,
    BtnCopy,
    BtnWroteItDown,
    BtnBack,
    BtnBackToPhrase,
    ConfirmPrompt,
    /// Template with `{}` for the word position (interpolated at the call site).
    WordNoTpl,
    AccountLabelOptional,
    AccountLabelHintWork,
    AccountLabelHintPersonal,
    BtnRestore,
    RestorePrompt,
    RestoreHint,
    // --- Ready screen: top bar + account switcher ---
    StatusConnected,
    StatusDisconnected,
    RelayReachable,
    RelayUnreachable,
    RelayUnknown,
    MyAddress,
    /// Template `Account: {}` — active account label interpolated at the call site.
    AccountLabelTpl,
    BtnAddAccount,
    // --- Ready screen: my-profile editor ---
    ProfileTitle,
    /// Template `My profile: {}` — own name interpolated at the call site.
    ProfileTitleNamedTpl,
    AvatarPathHint,
    BtnSetAvatar,
    BtnRemove,
    ProfileNameHint,
    ProfileBioHint,
    BtnSave,
    ProfileNoDescription,
    BtnEdit,
    // --- Ready screen: forwarding + search + contacts ---
    ForwardBanner,
    SearchHint,
    /// Template `found: {}` — hit count interpolated at the call site.
    SearchFoundTpl,
    DeleteContactHover,
    VerifiedHover,
    ContactsTitle,
    AddContactTitle,
    AddContactHint,
    ContactNameHint,
    AddressHint,
    BtnAdd,
    // --- Ready screen: status bar + blocked composer ---
    HistoryEncrypted,
    BlockedComposer,
    // --- Ready screen: composer ---
    /// Template `↩ Reply: {}` — quoted preview interpolated at the call site.
    ReplyBannerTpl,
    CancelReplyHover,
    EditingBanner,
    CancelEditHover,
    ComposeHint,
    BtnSendTimed,
    BtnSend,
    ExpiresLabel,
    ExpireOff,
    Expire30s,
    Expire5m,
    Expire1h,
    ExpiringNote,
    /// Template `{n} / {max} B` — both counts interpolated by named placeholders.
    CharCountTpl,
    FilePathHint,
    BtnSendFile,
    // --- Ready screen: chat header + safety number ---
    SelectContact,
    /// Template `· profile: {}` — declared name interpolated at the call site.
    ProfileHintTpl,
    SafetyVerified,
    SafetyUnverified,
    SafetyExplain,
    BtnMarkVerified,
    BtnClearChat,
    BtnUnblock,
    BtnBlock,
    BlockHover,
    // --- Ready screen: message bubble + context menu ---
    EditedMark,
    StatusSending,
    Cancelling,
    StatusFailed,
    /// Template `⏱ {} min` — minutes-left interpolated at the call site.
    ExpiryMinTpl,
    /// Template `⏱ {} s` — seconds-left interpolated at the call site.
    ExpirySecTpl,
    ToggleReactionHover,
    RightClickHover,
    BtnReply,
    BtnForward,
    BtnDeleteForMe,
    BtnDeleteForAll,
    CannotForceHover,

    // Status-line messages (localizable, detail-free). Error toasts that carry a
    // lower-layer diagnostic stay English (see `StatusMsg::Error`) — a localized
    // prefix glued to an untranslated detail reads worse than a consistent line.
    StUnlocked,
    StEnterPassword,
    StEnterRelayId,
    /// Template `word #{} does not match …` — the word position interpolated.
    StWordMismatchTpl,
    StSetPassword,
    StSwitching,
    StOwnAddress,
    StContactRenamed,
    StContactAdded,
    StContactDeleted,
    StChatCleared,
    StMessageDeleted,
    StDeletedForAll,
    StMarkedVerified,
    StPickForwardTarget,
    StForwarded,
    StLogInFirst,
    StUnlockFirst,
    StReadyToReceive,
    StRoutesOffered,
    StRoutesShared,
    StRoutesAccepted,
    StFileExported,
    BtnSaveAs,
    BtnShareRoutes,
    BtnAcceptRoutes,
    ShareRoutesHover,
    /// Template `file sent: {}` — the file name interpolated.
    StFileSentTpl,
    /// Template `profile: not delivered to {} contact(s)` — the count interpolated.
    StProfileNotDeliveredTpl,
    /// Template `avatar: not delivered to {} contact(s)` — the count interpolated.
    StAvatarNotDeliveredTpl,
    /// Template `message too long ({} B, limit {} B) …` — size then limit.
    StMsgTooLongTpl,
    /// Template `edit too long ({} B, limit {} B)` — size then limit.
    StEditTooLongTpl,
    /// Hover on the carrier chip in the status bar.
    CarrierHover,
    /// Button that opens a native file picker for attaching a file.
    BtnAttach,
    /// Menu button (⋮) holding per-chat actions (block / clear).
    ChatMenuHover,
}

/// Translate `key` into `lang`. Each arm is a row of 9 strings in `Lang::idx` order.
pub fn t(lang: Lang, key: Key) -> &'static str {
    let i = lang.idx();
    match key {
        Key::UnlockSubtitle => [
            "end-to-end encryption",
            "端到端加密",
            "cifrado de extremo a extremo",
            "criptografia de ponta a ponta",
            "enkripsi ujung-ke-ujung",
            "chiffrement de bout en bout",
            "エンドツーエンド暗号化",
            "сквозное шифрование",
            "Ende-zu-Ende-Verschlüsselung",
        ][i],
        Key::WelcomeSubtitleNew => [
            "private messenger · end-to-end encryption",
            "私密通讯 · 端到端加密",
            "mensajería privada · cifrado de extremo a extremo",
            "mensageiro privado · criptografia de ponta a ponta",
            "pesan pribadi · enkripsi ujung-ke-ujung",
            "messagerie privée · chiffrement de bout en bout",
            "プライベートメッセンジャー · エンドツーエンド暗号化",
            "приватный мессенджер · сквозное шифрование",
            "privater Messenger · Ende-zu-Ende-Verschlüsselung",
        ][i],
        Key::WelcomeSubtitleAdd => [
            "add another account",
            "添加另一个账户",
            "añadir otra cuenta",
            "adicionar outra conta",
            "tambah akun lain",
            "ajouter un autre compte",
            "別のアカウントを追加",
            "добавить ещё один аккаунт",
            "weiteres Konto hinzufügen",
        ][i],
        Key::WelcomeAddTitle => [
            "A new account is a separate identity (its own phrase).",
            "新账户是独立的身份（拥有自己的助记词）。",
            "Una cuenta nueva es una identidad aparte (con su propia frase).",
            "Uma conta nova é uma identidade separada (com sua própria frase).",
            "Akun baru adalah identitas terpisah (dengan frasa sendiri).",
            "Un nouveau compte est une identité distincte (avec sa propre phrase).",
            "新しいアカウントは別の身元です（独自のフレーズを持ちます）。",
            "Новый аккаунт — отдельная личность (своя фраза).",
            "Ein neues Konto ist eine eigene Identität (mit eigener Phrase).",
        ][i],
        Key::WelcomeAddNote => [
            "The device password and network settings are already set — no need to enter them again.",
            "设备密码和网络设置已配置——无需再次输入。",
            "La contraseña del dispositivo y la configuración de red ya están definidas: no hace falta volver a introducirlas.",
            "A senha do dispositivo e as configurações de rede já estão definidas — não é preciso inseri-las de novo.",
            "Kata sandi perangkat dan pengaturan jaringan sudah diatur — tidak perlu memasukkannya lagi.",
            "Le mot de passe de l'appareil et les paramètres réseau sont déjà définis — inutile de les saisir à nouveau.",
            "デバイスのパスワードとネットワーク設定は既に設定済みです。再入力は不要です。",
            "Пароль устройства и настройки сети уже заданы — вводить их снова не нужно.",
            "Gerätepasswort und Netzwerkeinstellungen sind bereits gesetzt — keine erneute Eingabe nötig.",
        ][i],
        Key::WelcomeNewTitle => [
            "No account has been created in this profile yet.",
            "此配置文件中尚未创建账户。",
            "Aún no se ha creado ninguna cuenta en este perfil.",
            "Ainda não há conta criada neste perfil.",
            "Belum ada akun yang dibuat di profil ini.",
            "Aucun compte n'a encore été créé dans ce profil.",
            "このプロファイルにはまだアカウントが作成されていません。",
            "Аккаунт в этом профиле ещё не создан.",
            "In diesem Profil wurde noch kein Konto erstellt.",
        ][i],
        Key::WelcomeNewNote => [
            "Your identity is a 12-word phrase (like a crypto wallet): it's all you need to sign in from any device.",
            "你的身份是一组 12 个单词的助记词（类似加密钱包）：凭它即可在任何设备上登录。",
            "Tu identidad es una frase de 12 palabras (como una billetera cripto): basta con ella para entrar desde cualquier dispositivo.",
            "Sua identidade é uma frase de 12 palavras (como uma carteira cripto): basta ela para entrar de qualquer dispositivo.",
            "Identitasmu adalah frasa 12 kata (seperti dompet kripto): cukup itu untuk masuk dari perangkat mana pun.",
            "Votre identité est une phrase de 12 mots (comme un portefeuille crypto) : elle suffit pour se connecter depuis n'importe quel appareil.",
            "あなたの身元は12単語のフレーズ（暗号ウォレットのようなもの）です。これだけでどの端末からでもサインインできます。",
            "Личность — это фраза из 12 слов (как в криптокошельке): её достаточно, чтобы войти с любого устройства.",
            "Deine Identität ist eine 12-Wörter-Phrase (wie eine Krypto-Wallet): damit meldest du dich auf jedem Gerät an.",
        ][i],
        Key::BtnCreateAccount => [
            "Create account",
            "创建账户",
            "Crear cuenta",
            "Criar conta",
            "Buat akun",
            "Créer un compte",
            "アカウントを作成",
            "Создать аккаунт",
            "Konto erstellen",
        ][i],
        Key::BtnRestorePhrase => [
            "Restore from phrase",
            "用助记词恢复",
            "Restaurar con la frase",
            "Restaurar pela frase",
            "Pulihkan dari frasa",
            "Restaurer depuis la phrase",
            "フレーズから復元",
            "Восстановить по фразе",
            "Mit Phrase wiederherstellen",
        ][i],
        Key::BtnCancel => [
            "Cancel", "取消", "Cancelar", "Cancelar", "Batal", "Annuler", "キャンセル", "Отмена", "Abbrechen",
        ][i],
        Key::BtnLogin => [
            "Sign in", "登录", "Entrar", "Entrar", "Masuk", "Se connecter", "サインイン", "Войти", "Anmelden",
        ][i],
        Key::LinkOtherAccount => [
            "create / restore another account",
            "创建 / 恢复其他账户",
            "crear / restaurar otra cuenta",
            "criar / restaurar outra conta",
            "buat / pulihkan akun lain",
            "créer / restaurer un autre compte",
            "別のアカウントを作成／復元",
            "создать / восстановить другой аккаунт",
            "anderes Konto erstellen / wiederherstellen",
        ][i],
        Key::FieldPassword => [
            "Password (encrypts secrets on this disk)",
            "密码（加密此磁盘上的机密）",
            "Contraseña (cifra los secretos en este disco)",
            "Senha (criptografa os segredos neste disco)",
            "Kata sandi (mengenkripsi rahasia di disk ini)",
            "Mot de passe (chiffre les secrets sur ce disque)",
            "パスワード（このディスク上の秘密を暗号化）",
            "Пароль (шифрует секреты на этом диске)",
            "Passwort (verschlüsselt Geheimnisse auf dieser Festplatte)",
        ][i],
        Key::NetRelay => ["Relay"; 9][i],
        Key::NetRelayId => ["Relay-id"; 9][i],
        Key::NetRelayIdHint => [
            "hex from karst-relay output",
            "来自 karst-relay 输出的 hex",
            "hex de la salida de karst-relay",
            "hex da saída do karst-relay",
            "hex dari keluaran karst-relay",
            "hex issu de la sortie de karst-relay",
            "karst-relay の出力の hex",
            "hex из вывода karst-relay",
            "Hex aus der karst-relay-Ausgabe",
        ][i],
        Key::NetSocks5 => [
            "SOCKS5 (Tor/obfs4, opt.)",
            "SOCKS5（Tor/obfs4，可选）",
            "SOCKS5 (Tor/obfs4, opc.)",
            "SOCKS5 (Tor/obfs4, opc.)",
            "SOCKS5 (Tor/obfs4, ops.)",
            "SOCKS5 (Tor/obfs4, opt.)",
            "SOCKS5（Tor/obfs4、任意）",
            "SOCKS5 (Tor/obfs4, опц.)",
            "SOCKS5 (Tor/obfs4, opt.)",
        ][i],
        Key::NetSocks5Hint => [
            "e.g. 127.0.0.1:9050",
            "例如 127.0.0.1:9050",
            "p. ej. 127.0.0.1:9050",
            "ex. 127.0.0.1:9050",
            "mis. 127.0.0.1:9050",
            "p. ex. 127.0.0.1:9050",
            "例：127.0.0.1:9050",
            "напр. 127.0.0.1:9050",
            "z. B. 127.0.0.1:9050",
        ][i],
        Key::NetRoutes => [
            "extra routes (failover)", "备用路由（故障转移）", "rutas adicionales (conmutación)", "rotas extras (failover)", "rute cadangan (failover)", "routes supplémentaires (bascule)", "予備の経路（フェイルオーバー）", "запасные маршруты (failover)", "zusätzliche Routen (Failover)",
        ][i],
        Key::NetRoutesHint => [
            "ip:port or wss@ip:port, comma-separated", "ip:port 或 wss@ip:port，逗号分隔", "ip:port o wss@ip:port, separados por comas", "ip:port ou wss@ip:port, separados por vírgula", "ip:port atau wss@ip:port, dipisah koma", "ip:port ou wss@ip:port, séparés par des virgules", "ip:port または wss@ip:port（カンマ区切り）", "ip:port или wss@ip:port, через запятую", "ip:port oder wss@ip:port, kommagetrennt",
        ][i],
        Key::NetExtraRelays => [
            "backup relays", "备用中继", "relays de respaldo", "relays de backup", "relay cadangan", "relais de secours", "予備リレー", "запасные relay", "Backup-Relays",
        ][i],
        Key::NetExtraRelaysHint => [
            "one 'addr relay-id' per line", "每行一个 'addr relay-id'", "un 'addr relay-id' por línea", "um 'addr relay-id' por linha", "satu 'addr relay-id' per baris", "un 'addr relay-id' par ligne", "1行につき 'addr relay-id' を1つ", "по одному 'addr relay-id' на строку", "ein 'addr relay-id' pro Zeile",
        ][i],
        Key::NetSection => [
            "Network (relay)",
            "网络（中继）",
            "Red (relay)",
            "Rede (relay)",
            "Jaringan (relay)",
            "Réseau (relay)",
            "ネットワーク（リレー）",
            "Сеть (relay)",
            "Netzwerk (Relay)",
        ][i],
        Key::LangLabel => [
            "Language", "语言", "Idioma", "Idioma", "Bahasa", "Langue", "言語", "Язык", "Sprache",
        ][i],
        Key::OnbSubtitleWrite => [
            "write down your recovery phrase",
            "抄写你的助记词",
            "anota tu frase de recuperación",
            "anote sua frase de recuperação",
            "catat frasa pemulihanmu",
            "notez votre phrase de récupération",
            "リカバリーフレーズを書き留める",
            "запишите фразу восстановления",
            "notiere deine Wiederherstellungsphrase",
        ][i],
        Key::OnbSubtitleVerify => [
            "verify your backup",
            "验证你的备份",
            "verifica tu copia de seguridad",
            "verifique seu backup",
            "verifikasi cadanganmu",
            "vérifiez votre sauvegarde",
            "バックアップを確認",
            "проверка резервной копии",
            "Sicherung überprüfen",
        ][i],
        Key::OnbSubtitleRestore => [
            "restore from phrase",
            "用助记词恢复",
            "restaurar con la frase",
            "restaurar pela frase",
            "pulihkan dari frasa",
            "restaurer depuis la phrase",
            "フレーズから復元",
            "восстановление по фразе",
            "mit Phrase wiederherstellen",
        ][i],
        Key::RecoveryPhraseTitle => [
            "Recovery phrase",
            "助记词",
            "Frase de recuperación",
            "Frase de recuperação",
            "Frasa pemulihan",
            "Phrase de récupération",
            "リカバリーフレーズ",
            "Фраза восстановления",
            "Wiederherstellungsphrase",
        ][i],
        Key::RecoveryPhraseWarn => [
            "The only way to recover the account. Write it on paper in order. Show it to no one; never store it in chats.",
            "这是找回账户的唯一方法。请按顺序抄在纸上。不要给任何人看，也不要保存在聊天里。",
            "La única forma de recuperar la cuenta. Anótala en papel en orden. No se la muestres a nadie ni la guardes en chats.",
            "A única forma de recuperar a conta. Anote no papel em ordem. Não mostre a ninguém nem guarde em conversas.",
            "Satu-satunya cara memulihkan akun. Tulis di kertas sesuai urutan. Jangan tunjukkan ke siapa pun, jangan simpan di obrolan.",
            "Le seul moyen de récupérer le compte. Notez-la sur papier dans l'ordre. Ne la montrez à personne, ne la stockez jamais dans des discussions.",
            "アカウントを復元する唯一の方法です。順番どおり紙に書いてください。誰にも見せず、チャットに保存しないでください。",
            "Единственный способ вернуть аккаунт. Запишите на бумаге по порядку. Не показывайте никому, не храните в переписке.",
            "Der einzige Weg, das Konto wiederherzustellen. Schreibe sie der Reihe nach auf Papier. Zeige sie niemandem und speichere sie nie in Chats.",
        ][i],
        Key::BtnCopy => [
            "📋 copy", "📋 复制", "📋 copiar", "📋 copiar", "📋 salin", "📋 copier", "📋 コピー", "📋 копировать", "📋 kopieren",
        ][i],
        Key::BtnWroteItDown => [
            "I wrote it down — continue",
            "我已抄好——继续",
            "Ya la anoté — continuar",
            "Já anotei — continuar",
            "Sudah dicatat — lanjut",
            "Je l'ai notée — continuer",
            "書き留めた — 続ける",
            "Я записал — продолжить",
            "Notiert — weiter",
        ][i],
        Key::BtnBack => [
            "Back", "返回", "Atrás", "Voltar", "Kembali", "Retour", "戻る", "Назад", "Zurück",
        ][i],
        Key::BtnBackToPhrase => [
            "Back to phrase",
            "返回助记词",
            "Volver a la frase",
            "Voltar à frase",
            "Kembali ke frasa",
            "Retour à la phrase",
            "フレーズに戻る",
            "Назад к фразе",
            "Zurück zur Phrase",
        ][i],
        Key::ConfirmPrompt => [
            "Enter the words from the phrase to confirm you saved it:",
            "输入助记词中的单词以确认你已保存：",
            "Introduce las palabras de la frase para confirmar que la guardaste:",
            "Digite as palavras da frase para confirmar que você a salvou:",
            "Masukkan kata-kata dari frasa untuk memastikan kamu menyimpannya:",
            "Saisissez les mots de la phrase pour confirmer que vous l'avez notée :",
            "フレーズを保存したことを確認するため、単語を入力してください：",
            "Введите слова из фразы, чтобы подтвердить запись:",
            "Gib die Wörter aus der Phrase ein, um zu bestätigen, dass du sie gespeichert hast:",
        ][i],
        Key::WordNoTpl => [
            "Word #{}", "第 {} 个词", "Palabra n.º {}", "Palavra nº {}", "Kata ke-{}", "Mot n° {}", "{} 番目の単語", "Слово №{}", "Wort Nr. {}",
        ][i],
        Key::AccountLabelOptional => [
            "Account name (optional)",
            "账户名称（可选）",
            "Nombre de la cuenta (opcional)",
            "Nome da conta (opcional)",
            "Nama akun (opsional)",
            "Nom du compte (facultatif)",
            "アカウント名（任意）",
            "Имя аккаунта (необязательно)",
            "Kontoname (optional)",
        ][i],
        Key::AccountLabelHintWork => [
            "e.g. Work", "例如 工作", "p. ej. Trabajo", "ex. Trabalho", "mis. Kerja", "p. ex. Travail", "例：仕事", "напр. Работа", "z. B. Arbeit",
        ][i],
        Key::AccountLabelHintPersonal => [
            "e.g. Personal", "例如 个人", "p. ej. Personal", "ex. Pessoal", "mis. Pribadi", "p. ex. Perso", "例：個人", "напр. Личный", "z. B. Privat",
        ][i],
        Key::BtnRestore => [
            "Restore", "恢复", "Restaurar", "Restaurar", "Pulihkan", "Restaurer", "復元", "Восстановить", "Wiederherstellen",
        ][i],
        Key::RestorePrompt => [
            "Enter the 12 words of your recovery phrase, separated by spaces:",
            "输入你的 12 个助记词，用空格分隔：",
            "Introduce las 12 palabras de tu frase de recuperación, separadas por espacios:",
            "Digite as 12 palavras da sua frase de recuperação, separadas por espaços:",
            "Masukkan 12 kata frasa pemulihanmu, dipisahkan spasi:",
            "Saisissez les 12 mots de votre phrase de récupération, séparés par des espaces :",
            "リカバリーフレーズの12単語をスペース区切りで入力してください：",
            "Введите 12 слов фразы восстановления через пробел:",
            "Gib die 12 Wörter deiner Wiederherstellungsphrase durch Leerzeichen getrennt ein:",
        ][i],
        Key::RestoreHint => [
            "word1 word2 … word12",
            "词1 词2 … 词12",
            "palabra1 palabra2 … palabra12",
            "palavra1 palavra2 … palavra12",
            "kata1 kata2 … kata12",
            "mot1 mot2 … mot12",
            "単語1 単語2 … 単語12",
            "слово1 слово2 … слово12",
            "Wort1 Wort2 … Wort12",
        ][i],
        // --- Ready screen: top bar + account switcher ---
        Key::StatusConnected => [
            "online", "在线", "en línea", "on-line", "daring", "en ligne", "オンライン", "на связи", "online",
        ][i],
        Key::StatusDisconnected => [
            "offline", "离线", "sin conexión", "off-line", "luring", "hors ligne", "オフライン", "нет связи", "offline",
        ][i],
        Key::RelayReachable => [
            "reachable", "可达", "accesible", "acessível", "dapat dijangkau", "joignable", "到達可能", "доступен", "erreichbar",
        ][i],
        Key::RelayUnreachable => [
            "unreachable", "不可达", "inaccesible", "inacessível", "tidak dapat dijangkau", "injoignable", "到達不能", "недоступен", "nicht erreichbar",
        ][i],
        Key::RelayUnknown => [
            "not polled yet", "尚未轮询", "aún sin sondear", "ainda não sondado", "belum dijajaki", "pas encore sondé", "未確認", "ещё не опрошен", "noch nicht geprüft",
        ][i],
        Key::MyAddress => [
            "my address:", "我的地址：", "mi dirección:", "meu endereço:", "alamat saya:", "mon adresse :", "自分のアドレス：", "мой адрес:", "meine Adresse:",
        ][i],
        Key::AccountLabelTpl => [
            "Account: {}", "账户：{}", "Cuenta: {}", "Conta: {}", "Akun: {}", "Compte : {}", "アカウント：{}", "Аккаунт: {}", "Konto: {}",
        ][i],
        Key::BtnAddAccount => [
            "+ Add account", "+ 添加账户", "+ Añadir cuenta", "+ Adicionar conta", "+ Tambah akun", "+ Ajouter un compte", "+ アカウントを追加", "+ Добавить аккаунт", "+ Konto hinzufügen",
        ][i],
        // --- Ready screen: my-profile editor ---
        Key::ProfileTitle => [
            "My profile", "我的资料", "Mi perfil", "Meu perfil", "Profil saya", "Mon profil", "マイプロフィール", "Мой профиль", "Mein Profil",
        ][i],
        Key::ProfileTitleNamedTpl => [
            "My profile: {}", "我的资料：{}", "Mi perfil: {}", "Meu perfil: {}", "Profil saya: {}", "Mon profil : {}", "マイプロフィール：{}", "Мой профиль: {}", "Mein Profil: {}",
        ][i],
        Key::AvatarPathHint => [
            "path to a PNG", "PNG 文件路径", "ruta a un PNG", "caminho para um PNG", "jalur ke file PNG", "chemin vers un PNG", "PNG ファイルのパス", "путь к PNG", "Pfad zu einer PNG",
        ][i],
        Key::BtnSetAvatar => [
            "Set avatar (PNG)", "设置头像 (PNG)", "Poner avatar (PNG)", "Definir avatar (PNG)", "Atur avatar (PNG)", "Définir l'avatar (PNG)", "アバターを設定 (PNG)", "Задать аватар (PNG)", "Avatar setzen (PNG)",
        ][i],
        Key::BtnRemove => [
            "Remove", "移除", "Quitar", "Remover", "Hapus", "Supprimer", "削除", "Убрать", "Entfernen",
        ][i],
        Key::ProfileNameHint => [
            "name", "名称", "nombre", "nome", "nama", "nom", "名前", "имя", "Name",
        ][i],
        Key::ProfileBioHint => [
            "about", "简介", "acerca de", "sobre", "tentang", "à propos", "自己紹介", "о себе", "über mich",
        ][i],
        Key::BtnSave => [
            "Save", "保存", "Guardar", "Salvar", "Simpan", "Enregistrer", "保存", "Сохранить", "Speichern",
        ][i],
        Key::ProfileNoDescription => [
            "no description", "无简介", "sin descripción", "sem descrição", "tanpa deskripsi", "aucune description", "説明なし", "нет описания", "keine Beschreibung",
        ][i],
        Key::BtnEdit => [
            "Edit", "编辑", "Editar", "Editar", "Ubah", "Modifier", "編集", "Изменить", "Bearbeiten",
        ][i],
        // --- Ready screen: forwarding + search + contacts ---
        Key::ForwardBanner => [
            "Forwarding → pick a chat", "转发 → 选择聊天", "Reenviando → elige un chat", "Encaminhando → escolha um chat", "Meneruskan → pilih obrolan", "Transfert → choisissez un chat", "転送 → チャットを選択", "Пересылка → выберите чат", "Weiterleiten → Chat wählen",
        ][i],
        Key::SearchHint => [
            "search the chats", "搜索聊天记录", "buscar en los chats", "pesquisar nas conversas", "cari di obrolan", "rechercher dans les chats", "チャットを検索", "поиск по переписке", "Chats durchsuchen",
        ][i],
        Key::SearchFoundTpl => [
            "found: {}", "找到：{}", "encontrado: {}", "encontrado: {}", "ditemukan: {}", "trouvé : {}", "見つかった：{}", "найдено: {}", "gefunden: {}",
        ][i],
        Key::DeleteContactHover => [
            "delete contact", "删除联系人", "eliminar contacto", "excluir contato", "hapus kontak", "supprimer le contact", "連絡先を削除", "удалить контакт", "Kontakt löschen",
        ][i],
        Key::VerifiedHover => [
            "verified", "已验证", "verificado", "verificado", "terverifikasi", "vérifié", "検証済み", "сверен", "verifiziert",
        ][i],
        Key::ContactsTitle => [
            "Contacts", "联系人", "Contactos", "Contatos", "Kontak", "Contacts", "連絡先", "Контакты", "Kontakte",
        ][i],
        Key::AddContactTitle => [
            "Add contact", "添加联系人", "Añadir contacto", "Adicionar contato", "Tambah kontak", "Ajouter un contact", "連絡先を追加", "Добавить контакт", "Kontakt hinzufügen",
        ][i],
        Key::AddContactHint => [
            "paste your peer's address (get it from them directly)", "粘贴对方的地址（当面向对方获取）", "pega la dirección de tu contacto (obtenla en persona)", "cole o endereço do seu contato (obtenha pessoalmente)", "tempel alamat lawan bicara (dapatkan langsung darinya)", "collez l'adresse de votre correspondant (obtenue en personne)", "相手のアドレスを貼り付け（本人から直接受け取る）", "вставьте адрес собеседника (получите его лично)", "Adresse des Kontakts einfügen (persönlich erhalten)",
        ][i],
        Key::ContactNameHint => [
            "name", "名称", "nombre", "nome", "nama", "nom", "名前", "имя", "Name",
        ][i],
        Key::AddressHint => [
            "address (64 hex)", "地址 (64 位十六进制)", "dirección (64 hex)", "endereço (64 hex)", "alamat (64 hex)", "adresse (64 hex)", "アドレス (64 桁の16進数)", "адрес (64 hex)", "Adresse (64 Hex)",
        ][i],
        Key::BtnAdd => [
            "Add", "添加", "Añadir", "Adicionar", "Tambah", "Ajouter", "追加", "Добавить", "Hinzufügen",
        ][i],
        // --- Ready screen: status bar + blocked composer ---
        Key::HistoryEncrypted => [
            "🔒 history and received files are encrypted on disk", "🔒 历史记录和收到的文件已在磁盘上加密", "🔒 el historial y los archivos recibidos están cifrados en disco", "🔒 histórico e arquivos recebidos são criptografados no disco", "🔒 riwayat dan file yang diterima dienkripsi di disk", "🔒 l'historique et les fichiers reçus sont chiffrés sur le disque", "🔒 履歴と受信ファイルはディスク上で暗号化", "🔒 история и принятые файлы шифруются на диске", "🔒 Verlauf und empfangene Dateien sind verschlüsselt",
        ][i],
        Key::BlockedComposer => [
            "🚫 contact blocked — incoming is refused; unblock to write", "🚫 联系人已屏蔽 — 拒收来信；解除屏蔽后可写", "🚫 contacto bloqueado — se rechaza lo entrante; desbloquea para escribir", "🚫 contato bloqueado — recebimento recusado; desbloqueie para escrever", "🚫 kontak diblokir — pesan masuk ditolak; buka blokir untuk menulis", "🚫 contact bloqué — l'entrant est refusé ; débloquez pour écrire", "🚫 連絡先をブロック中 — 受信は拒否。書くにはブロック解除", "🚫 контакт заблокирован — входящее не принимается; разблокируйте, чтобы писать", "🚫 Kontakt blockiert — Eingehendes wird abgelehnt; zum Schreiben entsperren",
        ][i],
        // --- Ready screen: composer ---
        Key::ReplyBannerTpl => [
            "↩ Reply: {}", "↩ 回复：{}", "↩ Responder: {}", "↩ Responder: {}", "↩ Balas: {}", "↩ Répondre : {}", "↩ 返信：{}", "↩ Ответ: {}", "↩ Antwort: {}",
        ][i],
        Key::CancelReplyHover => [
            "cancel reply", "取消回复", "cancelar respuesta", "cancelar resposta", "batalkan balasan", "annuler la réponse", "返信をキャンセル", "отменить ответ", "Antwort abbrechen",
        ][i],
        Key::EditingBanner => [
            "✎ Editing message", "✎ 正在编辑消息", "✎ Editando mensaje", "✎ Editando mensagem", "✎ Mengedit pesan", "✎ Modification du message", "✎ メッセージを編集中", "✎ Изменение сообщения", "✎ Nachricht bearbeiten",
        ][i],
        Key::CancelEditHover => [
            "cancel edit", "取消编辑", "cancelar edición", "cancelar edição", "batalkan edit", "annuler la modification", "編集をキャンセル", "отменить правку", "Bearbeitung abbrechen",
        ][i],
        Key::ComposeHint => [
            "message…", "消息…", "mensaje…", "mensagem…", "pesan…", "message…", "メッセージ…", "сообщение…", "Nachricht…",
        ][i],
        Key::BtnSendTimed => [
            "Send ⏱", "发送 ⏱", "Enviar ⏱", "Enviar ⏱", "Kirim ⏱", "Envoyer ⏱", "送信 ⏱", "Отправить ⏱", "Senden ⏱",
        ][i],
        Key::BtnSend => [
            "Send", "发送", "Enviar", "Enviar", "Kirim", "Envoyer", "送信", "Отправить", "Senden",
        ][i],
        Key::ExpiresLabel => [
            "⏱ disappears:", "⏱ 消失：", "⏱ desaparece:", "⏱ desaparece:", "⏱ menghilang:", "⏱ disparaît :", "⏱ 消える：", "⏱ исчезает:", "⏱ verschwindet:",
        ][i],
        Key::ExpireOff => [
            "off", "关", "no", "não", "mati", "désactivé", "オフ", "выкл", "aus",
        ][i],
        Key::Expire30s => [
            "30 s", "30 秒", "30 s", "30 s", "30 dtk", "30 s", "30 秒", "30 сек", "30 s",
        ][i],
        Key::Expire5m => [
            "5 min", "5 分钟", "5 min", "5 min", "5 mnt", "5 min", "5 分", "5 мин", "5 Min",
        ][i],
        Key::Expire1h => [
            "1 h", "1 小时", "1 h", "1 h", "1 jam", "1 h", "1 時間", "1 час", "1 Std",
        ][i],
        Key::ExpiringNote => [
            "the message is not written to disk; it disappears for both on the timer from send — or when the app closes, whichever comes first. Deletion cannot be forced on the recipient.",
            "该消息不会写入磁盘；从发送起按计时器在双方消失 — 或应用关闭时消失，以先到者为准。无法强制对方删除。",
            "el mensaje no se guarda en disco; desaparece en ambos según el temporizador desde el envío — o al cerrar la app, lo que ocurra primero. No se puede forzar el borrado en el destinatario.",
            "a mensagem não é gravada em disco; desaparece para ambos pelo temporizador desde o envio — ou ao fechar o app, o que vier primeiro. Não é possível forçar a exclusão no destinatário.",
            "pesan tidak ditulis ke disk; menghilang di kedua sisi sesuai timer sejak dikirim — atau saat aplikasi ditutup, mana yang lebih dulu. Penghapusan tidak dapat dipaksakan pada penerima.",
            "le message n'est pas écrit sur le disque ; il disparaît des deux côtés selon le minuteur depuis l'envoi — ou à la fermeture de l'app, au premier des deux. La suppression ne peut pas être imposée au destinataire.",
            "メッセージはディスクに書き込まれません。送信からのタイマーで両者から消えます — またはアプリを閉じた時、いずれか早い方で。受信者に削除を強制することはできません。",
            "сообщение не пишется на диск; исчезнет у обоих по таймеру от отправки — или при закрытии приложения, что раньше. Навязать удаление получателю нельзя.",
            "die Nachricht wird nicht auf die Festplatte geschrieben; sie verschwindet bei beiden gemäß Timer ab dem Senden — oder beim Schließen der App, je nachdem, was zuerst eintritt. Das Löschen kann dem Empfänger nicht aufgezwungen werden.",
        ][i],
        Key::CharCountTpl => [
            "{n} / {max} B", "{n} / {max} 字节", "{n} / {max} B", "{n} / {max} B", "{n} / {max} B", "{n} / {max} o", "{n} / {max} バイト", "{n} / {max} Б", "{n} / {max} B",
        ][i],
        Key::FilePathHint => [
            "path to a file", "文件路径", "ruta a un archivo", "caminho para um arquivo", "jalur ke file", "chemin vers un fichier", "ファイルのパス", "путь к файлу", "Pfad zu einer Datei",
        ][i],
        Key::BtnSendFile => [
            "Send file", "发送文件", "Enviar archivo", "Enviar arquivo", "Kirim file", "Envoyer le fichier", "ファイルを送信", "Отправить файл", "Datei senden",
        ][i],
        // --- Ready screen: chat header + safety number ---
        Key::SelectContact => [
            "Pick a contact on the left", "从左侧选择联系人", "Elige un contacto a la izquierda", "Escolha um contato à esquerda", "Pilih kontak di sebelah kiri", "Choisissez un contact à gauche", "左側の連絡先を選択", "Выберите контакт слева", "Wählen Sie links einen Kontakt",
        ][i],
        Key::ProfileHintTpl => [
            "· profile: {}", "· 资料：{}", "· perfil: {}", "· perfil: {}", "· profil: {}", "· profil : {}", "· プロフィール：{}", "· профиль: {}", "· Profil: {}",
        ][i],
        Key::SafetyVerified => [
            "🔑 Safety number · verified", "🔑 安全码 · 已验证", "🔑 Número de seguridad · verificado", "🔑 Número de segurança · verificado", "🔑 Nomor keamanan · terverifikasi", "🔑 Numéro de sécurité · vérifié", "🔑 安全番号 · 検証済み", "🔑 Код безопасности · сверен", "🔑 Sicherheitsnummer · verifiziert",
        ][i],
        Key::SafetyUnverified => [
            "🔑 Safety number (verify by voice/in person)", "🔑 安全码（通过语音/当面核对）", "🔑 Número de seguridad (verifica por voz/en persona)", "🔑 Número de segurança (verifique por voz/pessoalmente)", "🔑 Nomor keamanan (verifikasi lewat suara/langsung)", "🔑 Numéro de sécurité (vérifiez par la voix/en personne)", "🔑 安全番号（音声／対面で確認）", "🔑 Код безопасности (сверьте по голосу/лично)", "🔑 Sicherheitsnummer (per Stimme/persönlich prüfen)",
        ][i],
        Key::SafetyExplain => [
            "Matches on both sides — the addresses are authentic, no MITM.", "两边一致 — 地址真实，无中间人。", "Coincide en ambos lados — las direcciones son auténticas, sin intermediario.", "Coincide dos dois lados — os endereços são autênticos, sem intermediário.", "Cocok di kedua sisi — alamat asli, tanpa MITM.", "Identique des deux côtés — les adresses sont authentiques, pas d'intermédiaire.", "両側で一致 — アドレスは本物で、中間者はいません。", "Совпал у обоих — адреса подлинны, подмены нет.", "Stimmt auf beiden Seiten überein — die Adressen sind echt, kein MITM.",
        ][i],
        Key::BtnMarkVerified => [
            "Mark as verified", "标记为已验证", "Marcar como verificado", "Marcar como verificado", "Tandai terverifikasi", "Marquer comme vérifié", "検証済みにする", "Отметить сверенным", "Als verifiziert markieren",
        ][i],
        Key::BtnClearChat => [
            "clear the chat", "清空聊天", "vaciar el chat", "limpar a conversa", "kosongkan obrolan", "vider le chat", "チャットを消去", "очистить переписку", "Chat leeren",
        ][i],
        Key::BtnUnblock => [
            "unblock", "解除屏蔽", "desbloquear", "desbloquear", "buka blokir", "débloquer", "ブロック解除", "разблокировать", "entsperren",
        ][i],
        Key::BtnBlock => [
            "block", "屏蔽", "bloquear", "bloquear", "blokir", "bloquer", "ブロック", "заблокировать", "blockieren",
        ][i],
        Key::BlockHover => [
            "refuse incoming from this contact", "拒收此联系人的来信", "rechazar lo entrante de este contacto", "recusar recebimentos deste contato", "tolak pesan masuk dari kontak ini", "refuser l'entrant de ce contact", "この連絡先からの受信を拒否", "не принимать входящее от этого контакта", "Eingehendes von diesem Kontakt ablehnen",
        ][i],
        // --- Ready screen: message bubble + context menu ---
        Key::EditedMark => [
            "(edited)", "(已编辑)", "(editado)", "(editado)", "(diedit)", "(modifié)", "(編集済み)", "(изменено)", "(bearbeitet)",
        ][i],
        Key::StatusSending => [
            "sending…", "发送中…", "enviando…", "enviando…", "mengirim…", "envoi…", "送信中…", "отправляется…", "senden…",
        ][i],
        Key::Cancelling => [
            "cancel transfer", "取消传输", "cancelar transferencia", "cancelar transferência", "batalkan transfer", "annuler le transfert", "転送をキャンセル", "отменить передачу", "Übertragung abbrechen",
        ][i],
        Key::StatusFailed => [
            "not sent", "未发送", "no enviado", "não enviado", "tidak terkirim", "non envoyé", "未送信", "не отправлено", "nicht gesendet",
        ][i],
        Key::ExpiryMinTpl => [
            "⏱ {} min", "⏱ {} 分钟", "⏱ {} min", "⏱ {} min", "⏱ {} mnt", "⏱ {} min", "⏱ {} 分", "⏱ {} мин", "⏱ {} Min",
        ][i],
        Key::ExpirySecTpl => [
            "⏱ {} s", "⏱ {} 秒", "⏱ {} s", "⏱ {} s", "⏱ {} dtk", "⏱ {} s", "⏱ {} 秒", "⏱ {} сек", "⏱ {} s",
        ][i],
        Key::ToggleReactionHover => [
            "toggle reaction", "切换反应", "alternar reacción", "alternar reação", "alihkan reaksi", "basculer la réaction", "リアクションを切り替え", "снять/поставить", "Reaktion umschalten",
        ][i],
        Key::RightClickHover => [
            "right click — actions", "右键 — 操作", "clic derecho — acciones", "clique direito — ações", "klik kanan — tindakan", "clic droit — actions", "右クリック — 操作", "правый клик — действия", "Rechtsklick — Aktionen",
        ][i],
        Key::BtnReply => [
            "Reply", "回复", "Responder", "Responder", "Balas", "Répondre", "返信", "Ответить", "Antworten",
        ][i],
        Key::BtnForward => [
            "Forward", "转发", "Reenviar", "Encaminhar", "Teruskan", "Transférer", "転送", "Переслать", "Weiterleiten",
        ][i],
        Key::BtnDeleteForMe => [
            "Delete for me", "为我删除", "Eliminar para mí", "Excluir para mim", "Hapus untuk saya", "Supprimer pour moi", "自分から削除", "Удалить у себя", "Für mich löschen",
        ][i],
        Key::BtnDeleteForAll => [
            "Delete for everyone", "为所有人删除", "Eliminar para todos", "Excluir para todos", "Hapus untuk semua", "Supprimer pour tous", "全員から削除", "Удалить у всех", "Für alle löschen",
        ][i],
        Key::StUnlocked => [
            "unlocked", "已解锁", "desbloqueado", "desbloqueado", "terbuka", "déverrouillé", "ロック解除", "разблокировано", "entsperrt",
        ][i],
        Key::StEnterPassword => [
            "enter the password", "输入密码", "introduce la contraseña", "digite a senha", "masukkan kata sandi", "saisissez le mot de passe", "パスワードを入力", "введите пароль", "Passwort eingeben",
        ][i],
        Key::StEnterRelayId => [
            "enter the relay-id", "输入中继 ID", "introduce el relay-id", "digite o relay-id", "masukkan relay-id", "saisissez le relay-id", "リレー ID を入力", "введите relay-id", "Relay-ID eingeben",
        ][i],
        Key::StWordMismatchTpl => [
            "word #{} does not match — check your written copy",
            "第 {} 个词不匹配 — 请核对你的手写副本",
            "la palabra n.º {} no coincide — revisa tu copia escrita",
            "a palavra nº {} não confere — verifique sua cópia escrita",
            "kata ke-{} tidak cocok — periksa salinan tertulis Anda",
            "le mot n° {} ne correspond pas — vérifiez votre copie écrite",
            "{} 番目の単語が一致しません — 手書きの控えを確認してください",
            "слово №{} не совпадает — сверьтесь с записанной копией",
            "Wort Nr. {} stimmt nicht — prüfen Sie Ihre schriftliche Kopie",
        ][i],
        Key::StSetPassword => [
            "set a password (encrypts secrets on this disk)",
            "设置密码（加密此磁盘上的机密）",
            "establece una contraseña (cifra los secretos en este disco)",
            "defina uma senha (criptografa os segredos neste disco)",
            "atur kata sandi (mengenkripsi rahasia di disk ini)",
            "définissez un mot de passe (chiffre les secrets sur ce disque)",
            "パスワードを設定（このディスク上の秘密を暗号化）",
            "задайте пароль (шифрует секреты на этом диске)",
            "Passwort festlegen (verschlüsselt Geheimnisse auf dieser Festplatte)",
        ][i],
        Key::StSwitching => [
            "switching…", "切换中…", "cambiando…", "alternando…", "beralih…", "changement…", "切り替え中…", "переключение…", "wird gewechselt…",
        ][i],
        Key::StOwnAddress => [
            "that is your own address", "那是你自己的地址", "esa es tu propia dirección", "esse é o seu próprio endereço", "itu alamat Anda sendiri", "c'est votre propre adresse", "それはあなた自身のアドレスです", "это ваш собственный адрес", "das ist Ihre eigene Adresse",
        ][i],
        Key::StContactRenamed => [
            "contact renamed", "联系人已重命名", "contacto renombrado", "contato renomeado", "kontak diganti namanya", "contact renommé", "連絡先の名前を変更しました", "контакт переименован", "Kontakt umbenannt",
        ][i],
        Key::StContactAdded => [
            "contact added", "已添加联系人", "contacto añadido", "contato adicionado", "kontak ditambahkan", "contact ajouté", "連絡先を追加しました", "контакт добавлен", "Kontakt hinzugefügt",
        ][i],
        Key::StContactDeleted => [
            "contact deleted", "已删除联系人", "contacto eliminado", "contato excluído", "kontak dihapus", "contact supprimé", "連絡先を削除しました", "контакт удалён", "Kontakt gelöscht",
        ][i],
        Key::StChatCleared => [
            "chat cleared", "已清空聊天", "chat vaciado", "conversa limpa", "obrolan dibersihkan", "conversation effacée", "チャットを消去しました", "чат очищен", "Chat geleert",
        ][i],
        Key::StMessageDeleted => [
            "message deleted", "已删除消息", "mensaje eliminado", "mensagem excluída", "pesan dihapus", "message supprimé", "メッセージを削除しました", "сообщение удалено", "Nachricht gelöscht",
        ][i],
        Key::StDeletedForAll => [
            "deleted for everyone", "已为所有人删除", "eliminado para todos", "excluído para todos", "dihapus untuk semua", "supprimé pour tous", "全員から削除しました", "удалено у всех", "für alle gelöscht",
        ][i],
        Key::StMarkedVerified => [
            "contact marked verified", "已将联系人标记为已验证", "contacto marcado como verificado", "contato marcado como verificado", "kontak ditandai terverifikasi", "contact marqué comme vérifié", "連絡先を確認済みにしました", "контакт отмечен как проверенный", "Kontakt als verifiziert markiert",
        ][i],
        Key::StPickForwardTarget => [
            "pick a chat to forward to", "选择要转发到的聊天", "elige un chat para reenviar", "escolha uma conversa para encaminhar", "pilih obrolan tujuan penerusan", "choisissez une conversation où transférer", "転送先のチャットを選択", "выберите чат для пересылки", "Chat zum Weiterleiten auswählen",
        ][i],
        Key::StForwarded => [
            "forwarded", "已转发", "reenviado", "encaminhado", "diteruskan", "transféré", "転送しました", "переслано", "weitergeleitet",
        ][i],
        Key::StLogInFirst => [
            "log in first", "请先登录", "inicia sesión primero", "faça login primeiro", "masuk dulu", "connectez-vous d'abord", "先にログインしてください", "сначала войдите", "zuerst anmelden",
        ][i],
        Key::StUnlockFirst => [
            "unlock first", "请先解锁", "desbloquea primero", "desbloqueie primeiro", "buka kunci dulu", "déverrouillez d'abord", "先にロック解除してください", "сначала разблокируйте", "zuerst entsperren",
        ][i],
        Key::StReadyToReceive => [
            "ready to receive messages", "已准备好接收消息", "listo para recibir mensajes", "pronto para receber mensagens", "siap menerima pesan", "prêt à recevoir des messages", "メッセージを受信する準備ができました", "готов к приёму сообщений", "bereit zum Empfang von Nachrichten",
        ][i],
        Key::StRoutesOffered => [
            "a contact offered you extra routes", "联系人向你提供了备用路由", "un contacto te ofreció rutas adicionales", "um contato ofereceu rotas extras", "kontak menawarkan rute cadangan", "un contact vous propose des routes supplémentaires", "連絡先が予備の経路を提案しました", "контакт предложил вам запасные маршруты", "ein Kontakt hat dir zusätzliche Routen angeboten",
        ][i],
        Key::StRoutesShared => [
            "routes sent to this contact", "已把路由发送给该联系人", "rutas enviadas a este contacto", "rotas enviadas para este contato", "rute dikirim ke kontak ini", "routes envoyées à ce contact", "この連絡先に経路を送信しました", "маршруты отправлены этому контакту", "Routen an diesen Kontakt gesendet",
        ][i],
        Key::StRoutesAccepted => [
            "routes accepted — they will be tried too", "已接受路由，将一并尝试", "rutas aceptadas: también se probarán", "rotas aceitas — também serão tentadas", "rute diterima — akan ikut dicoba", "routes acceptées — elles seront aussi essayées", "経路を受け入れました（今後試します）", "маршруты приняты — теперь будут пробоваться и они", "Routen übernommen — sie werden mitprobiert",
        ][i],
        Key::StFileExported => [
            "file decrypted to the chosen location", "文件已解密到所选位置", "archivo descifrado en la ubicación elegida", "arquivo descriptografado no local escolhido", "file didekripsi ke lokasi pilihan", "fichier déchiffré vers l'emplacement choisi", "選んだ場所にファイルを復号しました", "файл расшифрован в выбранное место", "Datei an den gewählten Ort entschlüsselt",
        ][i],
        Key::BtnSaveAs => [
            "save as… (decrypts)", "另存为…（解密）", "guardar como… (descifra)", "salvar como… (descriptografa)", "simpan sebagai… (mendekripsi)", "enregistrer sous… (déchiffre)", "名前を付けて保存…（復号）", "сохранить как… (расшифрует)", "speichern unter… (entschlüsselt)",
        ][i],
        Key::BtnShareRoutes => [
            "share my routes", "分享我的路由", "compartir mis rutas", "compartilhar minhas rotas", "bagikan rute saya", "partager mes routes", "自分の経路を共有", "поделиться маршрутами", "meine Routen teilen",
        ][i],
        Key::BtnAcceptRoutes => [
            "accept offered routes", "接受对方提供的路由", "aceptar rutas ofrecidas", "aceitar rotas oferecidas", "terima rute yang ditawarkan", "accepter les routes proposées", "提案された経路を受け入れる", "принять предложенные маршруты", "angebotene Routen übernehmen",
        ][i],
        Key::ShareRoutesHover => [
            "tells this contact where you connect — share only with people you trust", "会告诉该联系人你的连接位置——只分享给你信任的人", "revela a este contacto por dónde te conectas: comparte solo con quien confíes", "revela a este contato por onde você se conecta — compartilhe só com quem confia", "memberi tahu kontak ini dari mana kamu terhubung — bagikan hanya ke orang tepercaya", "révèle à ce contact par où vous vous connectez — ne partagez qu'avec des personnes de confiance", "接続元をこの連絡先に伝えます。信頼できる相手にだけ共有してください", "покажет этому контакту, откуда вы подключаетесь — делитесь только с теми, кому доверяете", "verrät diesem Kontakt, worüber du dich verbindest — nur mit vertrauten Personen teilen",
        ][i],
        Key::StFileSentTpl => [
            "file sent: {}", "文件已发送：{}", "archivo enviado: {}", "arquivo enviado: {}", "berkas terkirim: {}", "fichier envoyé : {}", "ファイルを送信：{}", "файл отправлен: {}", "Datei gesendet: {}",
        ][i],
        Key::StProfileNotDeliveredTpl => [
            "profile: not delivered to {} contact(s)",
            "资料：未送达 {} 个联系人",
            "perfil: no entregado a {} contacto(s)",
            "perfil: não entregue a {} contato(s)",
            "profil: tidak terkirim ke {} kontak",
            "profil : non remis à {} contact(s)",
            "プロフィール：{} 件の連絡先に未達",
            "профиль: не доставлено {} контакту(ам)",
            "Profil: an {} Kontakt(e) nicht zugestellt",
        ][i],
        Key::StAvatarNotDeliveredTpl => [
            "avatar: not delivered to {} contact(s)",
            "头像：未送达 {} 个联系人",
            "avatar: no entregado a {} contacto(s)",
            "avatar: não entregue a {} contato(s)",
            "avatar: tidak terkirim ke {} kontak",
            "avatar : non remis à {} contact(s)",
            "アバター：{} 件の連絡先に未達",
            "аватар: не доставлено {} контакту(ам)",
            "Avatar: an {} Kontakt(e) nicht zugestellt",
        ][i],
        Key::StMsgTooLongTpl => [
            "message too long ({} B, limit {} B) — split it up",
            "消息过长（{} B，上限 {} B）— 请拆分",
            "mensaje demasiado largo ({} B, límite {} B) — divídelo",
            "mensagem muito longa ({} B, limite {} B) — divida-a",
            "pesan terlalu panjang ({} B, batas {} B) — pisahkan",
            "message trop long ({} B, limite {} B) — divisez-le",
            "メッセージが長すぎます（{} B、上限 {} B）— 分割してください",
            "сообщение слишком длинное ({} Б, лимит {} Б) — разбейте его",
            "Nachricht zu lang ({} B, Limit {} B) — teilen Sie sie auf",
        ][i],
        Key::StEditTooLongTpl => [
            "edit too long ({} B, limit {} B)",
            "编辑内容过长（{} B，上限 {} B）",
            "edición demasiado larga ({} B, límite {} B)",
            "edição muito longa ({} B, limite {} B)",
            "hasil edit terlalu panjang ({} B, batas {} B)",
            "modification trop longue ({} B, limite {} B)",
            "編集内容が長すぎます（{} B、上限 {} B）",
            "правка слишком длинная ({} Б, лимит {} Б)",
            "Bearbeitung zu lang ({} B, Limit {} B)",
        ][i],
        Key::BtnAttach => [
            "📎 Attach", "📎 附加", "📎 Adjuntar", "📎 Anexar", "📎 Lampirkan", "📎 Joindre", "📎 添付", "📎 Прикрепить", "📎 Anhängen",
        ][i],
        Key::ChatMenuHover => [
            "chat actions", "聊天操作", "acciones del chat", "ações da conversa", "tindakan obrolan", "actions de la conversation", "チャットの操作", "действия чата", "Chat-Aktionen",
        ][i],
        Key::CarrierHover => [
            "how KARST reaches the relay", "KARST 如何连接中继", "cómo KARST llega al relay", "como o KARST alcança o relay", "cara KARST menjangkau relay", "comment KARST atteint le relais", "KARST がリレーに到達する方法", "как KARST добирается до relay", "wie KARST den Relay erreicht",
        ][i],
        Key::CannotForceHover => [
            "cannot be forced on the recipient", "无法强制对方执行", "no se puede forzar al destinatario", "não pode ser forçado ao destinatário", "tidak dapat dipaksakan pada penerima", "ne peut pas être imposé au destinataire", "受信者に強制はできません", "нельзя навязать получателю", "kann dem Empfänger nicht aufgezwungen werden",
        ][i],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_langs_have_distinct_codes_and_names() {
        let mut codes: Vec<&str> = Lang::ALL.iter().map(|l| l.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), Lang::ALL.len(), "codes are distinct");
        // idx matches position in ALL.
        for (pos, l) in Lang::ALL.iter().enumerate() {
            assert_eq!(l.idx(), pos, "idx equals position in ALL");
        }
        // Round-trip through code.
        for l in Lang::ALL {
            assert_eq!(Lang::from_code(l.code()), Some(l));
        }
        assert_eq!(Lang::from_code("xx"), None);
    }

    #[test]
    fn every_language_column_is_non_empty_for_each_key() {
        // Guards against a short row (fewer than 9 entries would not compile, but an
        // empty string in a slot is a silent gap). English is the source of truth.
        let keys = [
            Key::UnlockSubtitle,
            Key::WelcomeSubtitleNew,
            Key::WelcomeSubtitleAdd,
            Key::WelcomeAddTitle,
            Key::WelcomeAddNote,
            Key::WelcomeNewTitle,
            Key::WelcomeNewNote,
            Key::BtnCreateAccount,
            Key::BtnRestorePhrase,
            Key::BtnCancel,
            Key::BtnLogin,
            Key::LinkOtherAccount,
            Key::FieldPassword,
            Key::NetRelay,
            Key::NetRelayId,
            Key::NetRelayIdHint,
            Key::NetSocks5,
            Key::NetSocks5Hint,
            Key::NetRoutes,
            Key::NetRoutesHint,
            Key::NetExtraRelays,
            Key::NetExtraRelaysHint,
            Key::NetSection,
            Key::LangLabel,
            Key::OnbSubtitleWrite,
            Key::OnbSubtitleVerify,
            Key::OnbSubtitleRestore,
            Key::RecoveryPhraseTitle,
            Key::RecoveryPhraseWarn,
            Key::BtnCopy,
            Key::BtnWroteItDown,
            Key::BtnBack,
            Key::BtnBackToPhrase,
            Key::ConfirmPrompt,
            Key::WordNoTpl,
            Key::AccountLabelOptional,
            Key::AccountLabelHintWork,
            Key::AccountLabelHintPersonal,
            Key::BtnRestore,
            Key::RestorePrompt,
            Key::RestoreHint,
            // Ready screen: top bar + account switcher
            Key::StatusConnected,
            Key::StatusDisconnected,
            Key::RelayReachable,
            Key::RelayUnreachable,
            Key::RelayUnknown,
            Key::MyAddress,
            Key::AccountLabelTpl,
            Key::BtnAddAccount,
            // Ready screen: my-profile editor
            Key::ProfileTitle,
            Key::ProfileTitleNamedTpl,
            Key::AvatarPathHint,
            Key::BtnSetAvatar,
            Key::BtnRemove,
            Key::ProfileNameHint,
            Key::ProfileBioHint,
            Key::BtnSave,
            Key::ProfileNoDescription,
            Key::BtnEdit,
            // Ready screen: forwarding + search + contacts
            Key::ForwardBanner,
            Key::SearchHint,
            Key::SearchFoundTpl,
            Key::DeleteContactHover,
            Key::VerifiedHover,
            Key::ContactsTitle,
            Key::AddContactTitle,
            Key::AddContactHint,
            Key::ContactNameHint,
            Key::AddressHint,
            Key::BtnAdd,
            // Ready screen: status bar + blocked composer
            Key::HistoryEncrypted,
            Key::BlockedComposer,
            // Ready screen: composer
            Key::ReplyBannerTpl,
            Key::CancelReplyHover,
            Key::EditingBanner,
            Key::CancelEditHover,
            Key::ComposeHint,
            Key::BtnSendTimed,
            Key::BtnSend,
            Key::ExpiresLabel,
            Key::ExpireOff,
            Key::Expire30s,
            Key::Expire5m,
            Key::Expire1h,
            Key::ExpiringNote,
            Key::CharCountTpl,
            Key::FilePathHint,
            Key::BtnSendFile,
            // Ready screen: chat header + safety number
            Key::SelectContact,
            Key::ProfileHintTpl,
            Key::SafetyVerified,
            Key::SafetyUnverified,
            Key::SafetyExplain,
            Key::BtnMarkVerified,
            Key::BtnClearChat,
            Key::BtnUnblock,
            Key::BtnBlock,
            Key::BlockHover,
            // Ready screen: message bubble + context menu
            Key::EditedMark,
            Key::StatusSending,
            Key::Cancelling,
            Key::StatusFailed,
            Key::ExpiryMinTpl,
            Key::ExpirySecTpl,
            Key::ToggleReactionHover,
            Key::RightClickHover,
            Key::BtnReply,
            Key::BtnForward,
            Key::BtnDeleteForMe,
            Key::BtnDeleteForAll,
            Key::CannotForceHover,
            Key::StUnlocked,
            Key::StEnterPassword,
            Key::StEnterRelayId,
            Key::StWordMismatchTpl,
            Key::StSetPassword,
            Key::StSwitching,
            Key::StOwnAddress,
            Key::StContactRenamed,
            Key::StContactAdded,
            Key::StContactDeleted,
            Key::StChatCleared,
            Key::StMessageDeleted,
            Key::StDeletedForAll,
            Key::StMarkedVerified,
            Key::StPickForwardTarget,
            Key::StForwarded,
            Key::StLogInFirst,
            Key::StUnlockFirst,
            Key::StReadyToReceive,
            Key::StRoutesOffered,
            Key::StRoutesShared,
            Key::StRoutesAccepted,
            Key::StFileExported,
            Key::BtnSaveAs,
            Key::BtnShareRoutes,
            Key::BtnAcceptRoutes,
            Key::ShareRoutesHover,
            Key::StFileSentTpl,
            Key::StProfileNotDeliveredTpl,
            Key::StAvatarNotDeliveredTpl,
            Key::StMsgTooLongTpl,
            Key::StEditTooLongTpl,
            Key::CarrierHover,
            Key::BtnAttach,
            Key::ChatMenuHover,
        ];
        // Placeholder templates must keep their `{}` / named slots after translation,
        // otherwise the call-site interpolation silently drops the value.
        let named_tpl = [Key::CharCountTpl];
        let brace_tpl = [
            Key::AccountLabelTpl,
            Key::ProfileTitleNamedTpl,
            Key::SearchFoundTpl,
            Key::ReplyBannerTpl,
            Key::ProfileHintTpl,
            Key::ExpiryMinTpl,
            Key::ExpirySecTpl,
            Key::StWordMismatchTpl,
            Key::StFileSentTpl,
            Key::StProfileNotDeliveredTpl,
            Key::StAvatarNotDeliveredTpl,
            Key::StMsgTooLongTpl,
            Key::StEditTooLongTpl,
        ];
        for k in keys {
            for l in Lang::ALL {
                assert!(!t(l, k).is_empty(), "empty translation for {:?}/{:?}", l, k);
                if brace_tpl.contains(&k) {
                    assert!(t(l, k).contains("{}"), "{:?}/{:?} lost its {{}} slot", l, k);
                }
                if named_tpl.contains(&k) {
                    assert!(
                        t(l, k).contains("{n}") && t(l, k).contains("{max}"),
                        "{:?}/{:?} lost a named slot",
                        l,
                        k
                    );
                }
            }
        }
    }
}
