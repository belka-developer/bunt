//! Страна сервера по его названию. Нужна для флага перед именем (FPTN и VLESS), как в мобильных клиентах.
//!
//! В токене у сервера есть только имя, адрес и порт, поэтому страна берётся из имени:
//! «Finland», «Финляндия», «fi-2», «🇫🇮 Helsinki» и так далее. Никаких запросов в сеть,
//! адрес сервера никуда не отправляется. Если страна не узнана, флага не будет.

/// Код страны (как имя файла в `ui/flags`) и названия через «|»: английское, русское и частые города.
const COUNTRIES: &[(&str, &str)] = &[
    ("fi", "finland|финляндия|helsinki|хельсинки"),
    ("de", "germany|германия|frankfurt|франкфурт|berlin|берлин|deutschland"),
    ("nl", "netherlands|нидерланды|голландия|holland|amsterdam|амстердам"),
    ("se", "sweden|швеция|stockholm|стокгольм"),
    ("no", "norway|норвегия|oslo|осло"),
    ("dk", "denmark|дания|copenhagen|копенгаген"),
    ("pl", "poland|польша|warsaw|варшава"),
    ("ee", "estonia|эстония|tallinn|таллин"),
    ("lv", "latvia|латвия|riga|рига"),
    ("lt", "lithuania|литва|vilnius|вильнюс"),
    ("fr", "france|франция|paris|париж"),
    ("gb", "united kingdom|great britain|britain|england|uk|великобритания|англия|london|лондон"),
    ("ie", "ireland|ирландия|dublin|дублин"),
    ("es", "spain|испания|madrid|мадрид"),
    ("it", "italy|италия|milan|милан|rome|рим"),
    ("pt", "portugal|португалия|lisbon|лиссабон"),
    ("ch", "switzerland|швейцария|zurich|цюрих"),
    ("at", "austria|австрия|vienna|вена"),
    ("be", "belgium|бельгия|brussels|брюссель"),
    ("cz", "czech republic|czechia|чехия|prague|прага"),
    ("sk", "slovakia|словакия"),
    ("hu", "hungary|венгрия|budapest|будапешт"),
    ("ro", "romania|румыния|bucharest|бухарест"),
    ("bg", "bulgaria|болгария|sofia|софия"),
    ("gr", "greece|греция|athens|афины"),
    ("tr", "turkey|turkiye|турция|istanbul|стамбул"),
    ("ua", "ukraine|украина|kyiv|kiev|киев"),
    ("by", "belarus|беларусь|белоруссия|minsk|минск"),
    ("kz", "kazakhstan|казахстан|almaty|алматы|astana|астана"),
    ("ru", "russia|россия|moscow|москва|saint petersburg|санкт-петербург"),
    ("us", "united states|usa|america|сша|америка|new york|нью-йорк|los angeles|лос-анджелес|chicago|miami|dallas|seattle"),
    ("ca", "canada|канада|toronto|торонто"),
    ("mx", "mexico|мексика"),
    ("br", "brazil|бразилия"),
    ("ar", "argentina|аргентина"),
    ("cl", "chile|чили"),
    ("jp", "japan|япония|tokyo|токио"),
    ("kr", "south korea|korea|южная корея|корея|seoul|сеул"),
    ("cn", "china|китай"),
    ("hk", "hong kong|гонконг"),
    ("tw", "taiwan|тайвань"),
    ("sg", "singapore|сингапур"),
    ("in", "india|индия|mumbai|мумбаи"),
    ("ae", "united arab emirates|uae|оаэ|эмираты|dubai|дубай"),
    ("il", "israel|израиль"),
    ("ge", "georgia|грузия|tbilisi|тбилиси"),
    ("am", "armenia|армения|yerevan|ереван"),
    ("az", "azerbaijan|азербайджан|baku|баку"),
    ("uz", "uzbekistan|узбекистан"),
    ("kg", "kyrgyzstan|киргизия|кыргызстан"),
    ("md", "moldova|молдова|молдавия"),
    ("rs", "serbia|сербия|belgrade|белград"),
    ("hr", "croatia|хорватия"),
    ("si", "slovenia|словения"),
    ("ba", "bosnia and herzegovina|bosnia|босния"),
    ("al", "albania|албания"),
    ("mk", "north macedonia|macedonia|северная македония|македония"),
    ("me", "montenegro|черногория"),
    ("lu", "luxembourg|люксембург"),
    ("is", "iceland|исландия"),
    ("cy", "cyprus|кипр"),
    ("mt", "malta|мальта"),
    ("za", "south africa|юар|южная африка"),
    ("au", "australia|австралия|sydney|сидней"),
    ("nz", "new zealand|новая зеландия"),
    ("th", "thailand|таиланд|bangkok|бангкок"),
    ("vn", "vietnam|вьетнам"),
    ("id", "indonesia|индонезия"),
    ("my", "malaysia|малайзия"),
    ("ph", "philippines|филиппины"),
];

fn code_known(c: &str) -> bool {
    COUNTRIES.iter().any(|(k, _)| *k == c)
}

/// Буквы флага-эмодзи («🇫🇮») переводятся в код страны.
fn emoji_code(s: &str) -> Option<String> {
    let mut letters = String::new();
    for ch in s.chars() {
        let u = ch as u32;
        if (0x1F1E6..=0x1F1FF).contains(&u) {
            letters.push((b'a' + (u - 0x1F1E6) as u8) as char);
            if letters.len() == 2 {
                break;
            }
        } else if letters.len() == 1 {
            letters.clear();
        }
    }
    (letters.len() == 2 && code_known(&letters)).then_some(letters)
}

/// Название без флагов-эмодзи: на Windows они выглядят как две буквы.
pub(crate) fn label(name: &str) -> String {
    let s: String = name.chars().filter(|c| !(0x1F1E6..=0x1F1FF).contains(&(*c as u32))).collect();
    let s = s.trim_matches(|c: char| c.is_whitespace() || c == '-' || c == '_' || c == '|');
    if s.is_empty() { name.trim().to_string() } else { s.to_string() }
}

/// Код страны сервера или пустая строка. `hint`: поле страны из токена, если оно там есть.
pub(crate) fn code_for(name: &str, hint: &str) -> String {
    let h = hint.trim().to_lowercase();
    if h.len() == 2 && code_known(&h) {
        return h;
    }
    if let Some(c) = emoji_code(name) {
        return c;
    }
    let l = label(name).to_lowercase();
    let words: Vec<&str> = l.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).collect();
    for (code, names) in COUNTRIES {
        for n in names.split('|') {
            if l == n {
                return code.to_string();
            }
        }
    }
    // название страны или города внутри имени: «Finland 2», «Германия, Франкфурт»
    for (code, names) in COUNTRIES {
        for n in names.split('|') {
            if n.len() < 4 {
                continue;
            }
            let nw: Vec<&str> = n.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).collect();
            if !nw.is_empty() && words.windows(nw.len()).any(|w| w == nw.as_slice()) {
                return code.to_string();
            }
        }
    }
    // двухбуквенный код только в начале имени: «de-1», «fi_hel»
    if let Some(first) = words.first() {
        if first.len() == 2 && code_known(first) {
            return first.to_string();
        }
    }
    // двухбуквенный код ЗАГЛАВНЫМИ в любом месте: «VLESS RU 1», «Reality-DE-02», «[SE] Stockholm».
    // Строчные не берём: «no», «in», «is» бывают просто словами.
    for w in label(name).split(|c: char| !c.is_alphanumeric()) {
        if w.len() == 2 && w.chars().all(|c| c.is_ascii_uppercase()) {
            let lw = w.to_lowercase();
            if lw == "uk" {
                return "gb".to_string();
            }
            if code_known(&lw) {
                return lw;
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn by_name() {
        assert_eq!(code_for("Finland", ""), "fi");
        assert_eq!(code_for("Германия", ""), "de");
        assert_eq!(code_for("Finland 2", ""), "fi");
        assert_eq!(code_for("United States", ""), "us");
        assert_eq!(code_for("Нидерланды, Амстердам", ""), "nl");
        assert_eq!(code_for("de-1", ""), "de");
        assert_eq!(code_for("fi_hel", ""), "fi");
        assert_eq!(code_for("Server", ""), "");
        assert_eq!(code_for("no way", ""), "no");
    }

    #[test]
    fn by_uppercase_code() {
        assert_eq!(code_for("VLESS RU 1", ""), "ru");
        assert_eq!(code_for("Reality-DE-02", ""), "de");
        assert_eq!(code_for("[SE] Stockholm", ""), "se");
        assert_eq!(code_for("Premium UK", ""), "gb");
        assert_eq!(code_for("Reality in the dark", ""), "");
        assert_eq!(code_for("TURBO-01", ""), "");
    }

    #[test]
    fn by_emoji_and_hint() {
        assert_eq!(code_for("🇫🇮 Helsinki 1", ""), "fi");
        assert_eq!(code_for("🇩🇪Server", ""), "de");
        assert_eq!(label("🇫🇮 Helsinki 1"), "Helsinki 1");
        assert_eq!(label("Finland"), "Finland");
        assert_eq!(code_for("anything", "SE"), "se");
        assert_eq!(code_for("anything", "zz"), "");
    }
}
