<?php

declare(strict_types=1);

function h(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function viewUrl(string $view, array $filters = []): string
{
    return '?' . http_build_query(['view' => $view] + array_filter($filters, static fn ($value) => $value !== ''), '', '&', PHP_QUERY_RFC3986);
}

function hidden(string $name, string $value): void
{
    echo '<input type="hidden" name="' . h($name) . '" value="' . h($value) . '">';
}

function formAction(string $action): void
{
    hidden('csrf', $_SESSION['csrf']);
    hidden('action', $action);
}

function passwordField(string $label = 'Current password'): void
{
    echo '<label>' . h(t($label)) . '<input type="password" name="password" autocomplete="current-password" maxlength="72" required></label>';
}

function languageLink(string $language, string $view, array $filters): void
{
    $next = $language === 'en' ? 'fa' : 'en';
    $label = $next === 'fa' ? 'فارسی' : 'English';
    $url = viewUrl($view === 'rotate' ? 'overview' : $view, ['lang' => $next] + $filters);
    echo '<a class="button quiet language-link" href="' . h($url) . '" lang="' . h($next) . '">' . h($label) . '</a>';
}

function eventLabel(string $decision): string
{
    return ['block' => t('Blocked'), 'reject' => t('Rejected'), 'monitor' => t('Logged'), 'shadow' => t('Shadow')][$decision] ?? t('Recorded');
}

function statusLabel(string $label, string $tone): void
{
    echo '<span class="status ' . h($tone) . '"><i aria-hidden="true"></i>' . h($label) . '</span>';
}

function utcTime(string $value): string
{
    return str_replace('T', ' ', substr($value, 0, 19));
}

function eventTable(array $rows, bool $compact = false, array $filters = [], string $selected = ''): void
{
    ?>
    <div class="table-wrap">
      <table class="event-table">
        <thead><tr><th scope="col"><?= h(t('Time')) ?> <bdi>UTC</bdi></th><th scope="col"><?= h(t('Source IP')) ?></th><th scope="col"><?= h(t('Request')) ?></th><th scope="col"><?= h(t('Rule')) ?></th><th scope="col"><?= h(t('Action')) ?></th><?php if (!$compact): ?><th scope="col"><?= h(t('Score')) ?></th><?php endif; ?><th scope="col"><?= h(t('Details')) ?></th></tr></thead>
        <tbody>
        <?php foreach ($rows as $row):
            $decision = (string) ($row['decision'] ?? '');
            $ref = (string) ($row['reference'] ?? '');
            $isSelected = $ref !== '' && $ref === $selected;
            $route = (string) ($row['uri'] ?? '/');
            $rules = $row['rule_ids'] ?? [];
            ?>
          <tr<?= $isSelected ? ' class="selected-row"' : '' ?>>
            <td class="nowrap"><bdi class="mono subtle"><?= h(utcTime((string) ($row['ts'] ?? ''))) ?></bdi></td>
            <td><bdi class="mono"><?= h($row['ip'] ?? '-') ?></bdi></td>
            <td><div class="request-cell" dir="ltr"><span class="method"><?= h($row['method'] ?? '-') ?></span><bdi class="route" title="<?= h($route) ?>"><?= h($route) ?></bdi></div></td>
            <td class="nowrap"><bdi class="mono"><?= h(implode(', ', array_slice($rules, 0, 2))) ?></bdi><?php if (count($rules) > 2): ?> <bdi class="subtle">+<?= count($rules) - 2 ?></bdi><?php endif; ?></td>
            <td><?php statusLabel(eventLabel($decision), in_array($decision, ['block', 'reject'], true) ? 'negative' : 'warning'); ?></td>
            <?php if (!$compact): ?><td><bdi class="mono"><?= (int) ($row['score'] ?? 0) ?></bdi></td><?php endif; ?>
            <td><?php if ($ref !== ''): ?><a class="text-link" href="<?= h(viewUrl('attacks', ['event' => $ref] + $filters)) ?>"<?= $isSelected ? ' aria-current="true"' : '' ?>><?= h(t('View')) ?></a><?php else: ?>—<?php endif; ?></td>
          </tr>
        <?php endforeach; ?>
        <?php if ($rows === []): ?><tr><td class="empty" colspan="<?= $compact ? 6 : 7 ?>"><?= h(t('No events to display.')) ?></td></tr><?php endif; ?>
        </tbody>
      </table>
    </div>
    <?php
}

$titles = ['overview' => t('Dashboard'), 'attacks' => t('Attack Log'), 'signatures' => t('Signatures'), 'exceptions' => t('Exceptions'), 'access' => t('Access Management'), 'rotate' => t('Change initial password')];
$navigation = [t('Monitoring') => ['overview', 'attacks'], t('Firewall Policy') => ['signatures', 'exceptions'], t('System') => ['access']];
$active = !empty($settings['active']);
$modeLabel = strtoupper((string) ($settings['engine']['mode'] ?? 'filter'));
$blocked = array_filter($events, static fn ($row) => in_array($row['decision'] ?? '', ['block', 'reject'], true));
$ips = array_filter(array_unique(array_column($blocked, 'ip')), static fn ($value) => $value !== '-');
$exceptions = $settings['exceptions'] ?? [];
$currentExceptions = array_filter($exceptions, static fn ($row) => ($row['expires'] ?? 0) > time());
$connected = count(array_filter($entries, static fn ($row) => $row['status'] === 'installed'));
?>
<!doctype html>
<html lang="<?= h($language) ?>" dir="<?= $language === 'fa' ? 'rtl' : 'ltr' ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= h($signedIn ? $titles[$view] : t('Sign in')) ?> | Firewall</title>
<style nonce="<?= h($nonce) ?>"><?= file_get_contents(__DIR__ . '/panel.css') ?></style>
</head>
<body>
<?php if (!$signedIn || $mustRotate): ?>
<main class="login">
  <section class="login-box" aria-labelledby="login-title">
    <header class="login-head"><bdi class="brand">PHPWAF</bdi><?php languageLink($language, $view, $context); ?></header>
    <div class="login-content">
      <h1 id="login-title"><?= h($signedIn ? t('Change initial password') : t('Sign in to the console')) ?></h1>
      <?php if (is_array($message)): ?><p class="notice error" role="status"><?= h(t($message[1])) ?></p><?php endif; ?>
      <?php if ($signedIn): ?>
        <p class="subtle setup-note"><?= h(t('Set a new password of at least 16 bytes to unlock the console. You can keep the username admin.')) ?></p>
        <form method="post" class="stack">
          <?php formAction('credentials'); ?>
          <label><?= h(t('Username')) ?><input type="text" name="username" value="<?= h($auth['username']) ?>" autocomplete="username" maxlength="40" required dir="ltr"></label>
          <?php passwordField(); ?>
          <label><?= h(t('New password')) ?><input name="new_password" type="password" autocomplete="new-password" minlength="16" maxlength="72" required></label>
          <label><?= h(t('Confirm new password')) ?><input name="confirm_password" type="password" autocomplete="new-password" minlength="16" maxlength="72" required></label>
          <button class="button primary" type="submit"><?= h(t('Set new password')) ?></button>
        </form>
        <form method="post" class="setup-exit"><?php formAction('logout'); ?><button class="button quiet" type="submit"><?= h(t('Sign out')) ?></button></form>
      <?php else: ?>
        <form method="post" class="stack">
          <?php formAction('login'); ?>
          <label><?= h(t('Username')) ?><input type="text" name="username" autocomplete="username" maxlength="40" required autofocus dir="ltr"></label>
          <?php passwordField('Password'); ?>
          <?php if ($showSetupCode): ?>
            <label><?= h(t('First sign-in setup code')) ?><input type="password" name="setup_code" autocomplete="off" maxlength="48" required></label>
          <?php endif; ?>
          <button class="button primary" type="submit"><?= h(t('Sign in')) ?></button>
        </form>
      <?php endif; ?>
    </div>
  </section>
</main>
<?php else: ?>
<div class="console">
  <header class="topbar">
    <a class="brand" dir="ltr" href="?view=overview" aria-label="<?= h(t('PHPWAF dashboard')) ?>">PHPWAF</a>
    <div class="top-status">
      <?php statusLabel($active ? t('Firewall enabled') : t('Firewall disabled'), $active ? 'positive' : 'neutral'); ?>
      <bdi class="mono top-mode"><?= h($modeLabel) ?></bdi>
    </div>
    <div class="operator">
      <bdi class="mono"><?= h($auth['username']) ?></bdi>
      <?php languageLink($language, $view, $context); ?>
      <form method="post"><?php formAction('logout'); ?><button class="button quiet" type="submit"><?= h(t('Sign out')) ?></button></form>
    </div>
  </header>
  <div class="shell">
    <aside class="sidebar">
      <nav aria-label="<?= h(t('Main navigation')) ?>">
      <?php foreach ($navigation as $group => $items): $groupId = 'nav-' . $items[0]; ?>
        <section class="nav-group" aria-labelledby="<?= h($groupId) ?>">
          <h2 class="nav-title" id="<?= h($groupId) ?>"><?= h($group) ?></h2>
          <div class="nav-links">
            <?php foreach ($items as $key): ?>
            <a href="<?= h(viewUrl($key)) ?>"<?= $view === $key ? ' aria-current="page"' : '' ?>><?= h($titles[$key]) ?></a>
            <?php endforeach; ?>
          </div>
        </section>
      <?php endforeach; ?>
      </nav>
    </aside>
    <main class="workspace">
      <div class="page-head"><h1><?= h($titles[$view]) ?></h1></div>
      <?php if (is_array($message)): ?><p class="notice <?= $message[0] === 'ok' ? 'ok' : 'error' ?>" role="status"><?= h(t($message[1])) ?></p><?php endif; ?>
      <?php if ($view === 'overview'): ?>
        <section class="panel">
          <div class="section-head"><h2><?= h(t('Status Overview')) ?></h2><span class="subtle"><?= h(t('Based on recent events')) ?></span></div>
          <dl class="metrics">
            <div><dt><?= h(t('Rejected Requests')) ?></dt><dd><?= count($blocked) ?></dd></div>
            <div><dt><?= h(t('Unique Source IPs')) ?></dt><dd><?= count($ips) ?></dd></div>
            <div><dt><?= h(t('Active Exceptions')) ?></dt><dd><a href="?view=exceptions"><?= count($currentExceptions) ?></a></dd></div>
            <div><dt><?= h(t('Protected Entry Points')) ?></dt><dd><bdi><?= $connected ?> <span class="subtle">/ <?= count($entries) ?></span></bdi></dd></div>
          </dl>
        </section>
        <div class="dashboard-columns">
          <section class="panel">
            <div class="section-head"><h2><?= h(t('Installation Status')) ?></h2></div>
            <div class="table-wrap">
              <table class="plain-table">
                <thead><tr><th scope="col"><?= h(t('PHP entry point')) ?></th><th scope="col"><?= h(t('Connection')) ?></th></tr></thead>
                <tbody>
                  <?php foreach ($entries as $entry):
                      $stateLabel = ['installed' => t('Attached'), 'ready' => t('Ready'), 'conflict' => t('Review required'), 'unavailable' => t('Unavailable')];
                      $stateTone = ['installed' => 'positive', 'ready' => 'neutral', 'conflict' => 'warning', 'unavailable' => 'negative'];
                      ?>
                    <tr><td><bdi class="mono"><?= h($entry['file']) ?></bdi></td><td><?php statusLabel($stateLabel[$entry['status']], $stateTone[$entry['status']]); ?></td></tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
            <div class="panel-foot">
              <form method="post" class="inline-form"><?php formAction($active ? 'disable' : 'enable'); ?><?php passwordField(); ?>
                <button class="button <?= $active ? 'danger' : 'primary' ?>" type="submit"><?= $active ? t('Disable firewall') : t('Enable firewall') ?></button>
              </form>
              <?php if (!$active && $connected > 0): ?>
                <form method="post" class="inline-form"><?php formAction('disable'); ?><?php passwordField(); ?>
                  <button class="button secondary" type="submit"><?= h(t('Remove remaining hooks')) ?></button>
                </form>
              <?php endif; ?>
              <form method="post" class="inline-form">
                <?php formAction('mode'); ?>
                <label><?= h(t('Inspection mode')) ?><select name="mode">
                  <?php foreach (['monitor' => 'Monitor', 'filter' => 'Filter', 'enforce' => 'Enforce'] as $value => $label): ?>
                    <option value="<?= h($value) ?>"<?= $modeLabel === strtoupper($value) ? ' selected' : '' ?>><?= h(t($label)) ?></option>
                  <?php endforeach; ?>
                </select></label>
                <?php passwordField(); ?>
                <button class="button secondary" type="submit"><?= h(t('Save mode')) ?></button>
              </form>
            </div>
          </section>
          <section class="panel">
            <div class="section-head"><h2><?= h(t('Most Triggered Rules')) ?></h2><a class="text-link" href="?view=signatures"><?= h(t('Signatures')) ?></a></div>
            <?php
            $rules = [];
            foreach ($blocked as $row) {
                foreach ($row['rule_ids'] ?? [] as $rule) {
                    $rules[$rule] = ($rules[$rule] ?? 0) + 1;
                }
            }
            arsort($rules);
            ?>
            <div class="rule-stats">
              <?php foreach (array_slice($rules, 0, 5, true) as $rule => $count): ?>
                <div class="chart-row"><a class="mono" href="<?= h(viewUrl('attacks', ['q' => $rule])) ?>"><?= h($rule) ?></a><meter aria-label="<?= h($rule) ?>" min="0" max="<?= max($rules) ?>" value="<?= $count ?>"><?= $count ?></meter><bdi class="mono"><?= $count ?></bdi></div>
              <?php endforeach; ?>
              <?php if ($rules === []): ?><p class="empty"><?= h(t('No blocking rule appears in recent events.')) ?></p><?php endif; ?>
            </div>
          </section>
        </div>
        <section class="panel">
          <div class="section-head"><h2><?= h(t('Recent Events')) ?></h2><a class="text-link" href="?view=attacks"><?= h(t('Open Attack Log')) ?></a></div>
          <?php eventTable(array_slice($events, 0, 8), true); ?>
        </section>
      <?php elseif ($view === 'attacks'): ?>
        <?php
        $q = $context['q'] ?? '';
        $decision = $context['decision'] ?? '';
        $method = $context['method'] ?? '';
        $methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
        $filtered = array_values(array_filter($events, static function ($row) use ($q, $decision, $method): bool {
            $searchable = implode(' ', [$row['ip'] ?? '', $row['uri'] ?? '', $row['reference'] ?? '', implode(' ', $row['rule_ids'] ?? [])]);
            return ($decision === '' || ($row['decision'] ?? '') === $decision)
                && ($method === '' || ($row['method'] ?? '') === $method)
                && ($q === '' || mb_stripos($searchable, $q, 0, 'UTF-8') !== false);
        }));
        $pages = max(1, (int) ceil(count($filtered) / 25));
        $page = max(1, min($pages, (int) ($context['page'] ?? 1)));
        $filters = ['q' => $q, 'decision' => $decision, 'method' => $method, 'page' => $page > 1 ? (string) $page : ''];
        ?>
        <?php if ($reference !== '' && $event === null): ?><p class="notice error"><?= h(t('This event is outside the recent log.')) ?></p><?php endif; ?>
        <div class="master-detail<?= $event !== null ? ' with-inspector' : '' ?>">
          <section class="panel master">
            <form method="get" class="filterbar" aria-label="<?= h(t('Attack log filters')) ?>">
              <?php hidden('view', 'attacks'); ?>
              <label class="filter-search"><?= h(t('Search')) ?><input name="q" value="<?= h($q) ?>" maxlength="128" placeholder="<?= h(t('IP, path, rule, or reference')) ?>"></label>
              <label><?= h(t('Action')) ?><select name="decision"><option value=""><?= h(t('All')) ?></option>
                <?php foreach (['block', 'reject', 'monitor', 'shadow'] as $option): ?><option value="<?= h($option) ?>"<?= $decision === $option ? ' selected' : '' ?>><?= h(eventLabel($option)) ?></option><?php endforeach; ?>
              </select></label>
              <label><?= h(t('Method')) ?><select name="method"><option value=""><?= h(t('All')) ?></option>
                <?php foreach ($methods as $option): ?><option value="<?= h($option) ?>"<?= $method === $option ? ' selected' : '' ?>><?= h($option) ?></option><?php endforeach; ?>
              </select></label>
              <button class="button secondary" type="submit"><?= h(t('Apply')) ?></button>
              <?php if ($q !== '' || $decision !== '' || $method !== ''): ?><a class="button quiet" href="?view=attacks"><?= h(t('Clear')) ?></a><?php endif; ?>
            </form>
            <?php eventTable(array_slice($filtered, ($page - 1) * 25, 25), $event !== null, $filters, $reference); ?>
            <div class="table-foot">
              <span><?= h(t('%d of %d recent events', count($filtered), count($events))) ?></span>
              <?php if ($pages > 1): ?><nav class="pager" aria-label="<?= h(t('Log pages')) ?>">
                <?php for ($i = 1; $i <= $pages; ++$i): ?>
                  <a<?= $i === $page ? ' aria-current="page"' : '' ?> href="<?= h(viewUrl('attacks', ['page' => (string) $i, 'event' => $reference] + $filters)) ?>"><?= $i ?></a>
                <?php endfor; ?>
              </nav><?php endif; ?>
            </div>
          </section>
          <?php if ($event !== null): ?>
            <aside class="panel inspector" aria-label="<?= h(t('Request Details')) ?>">
              <div class="section-head"><h2><?= h(t('Request Details')) ?></h2><a class="text-link" href="<?= h(viewUrl('attacks', $filters)) ?>"><?= h(t('Close')) ?></a></div>
              <div class="inspector-content">
                <dl class="facts">
                  <dt><?= h(t('Event reference')) ?></dt><dd><bdi class="mono"><?= h($event['reference']) ?></bdi></dd>
                  <dt><?= h(t('Time (UTC)')) ?></dt><dd><bdi class="mono"><?= h(utcTime((string) ($event['ts'] ?? ''))) ?></bdi></dd>
                  <dt><?= h(t('Source IP')) ?></dt><dd><bdi class="mono"><?= h($event['ip'] ?? '-') ?></bdi></dd>
                  <dt><?= h(t('Request')) ?></dt><dd><bdi class="mono"><?= h(($event['method'] ?? '') . ' ' . ($event['uri'] ?? '')) ?></bdi></dd>
                  <dt><?= h(t('Action')) ?></dt><dd><?= h(eventLabel($event['decision'] ?? '')) ?></dd>
                  <dt><?= h(t('Score')) ?></dt><dd><bdi class="mono"><?= (int) ($event['score'] ?? 0) ?></bdi></dd>
                  <?php if (!empty($event['types'])): ?><dt><?= h(t('Reason')) ?></dt><dd><bdi><?= h(implode(' · ', array_map('t', $event['types']))) ?></bdi></dd><?php endif; ?>
                </dl>
                <h3 class="inspector-subhead"><?= h(t('Match Evidence')) ?></h3>
                <?php foreach ($event['evidence'] ?? [] as $index => $item): ?>
                  <div class="evidence">
                    <div class="evidence-head"><bdi class="mono"><?= h($item['rule']) ?></bdi><bdi class="mono subtle"><?= h($item['source'] . ' ' . $item['field']) ?></bdi></div>
                    <?php if ($item['sample'] !== null): ?><pre dir="ltr"><?= h($item['sample']) ?></pre><?php else: ?><p class="subtle"><?= h(t('This value is hidden in the log.')) ?></p><?php endif; ?>
                    <?php if (($event['decision'] ?? '') === 'block' && isset($item['fingerprint'])): ?>
                      <form method="post" class="stack"><?php formAction('add-exception'); ?>
                        <?php hidden('reference', $event['reference']); hidden('evidence', (string) $index); ?>
                        <div class="inline-form">
                          <label class="days"><?= h(t('Expires in (days)')) ?><input name="days" type="number" min="1" max="30" value="7" required></label>
                          <?php passwordField(); ?>
                        </div>
                        <button class="button secondary" type="submit"><?= h(t('Add exception for this match')) ?></button>
                      </form>
                    <?php endif; ?>
                  </div>
                <?php endforeach; ?>
                <?php if (empty($event['evidence'])): ?><p class="subtle"><?= h(t('No match evidence is available for this event.')) ?></p><?php endif; ?>
              </div>
            </aside>
          <?php endif; ?>
        </div>
      <?php elseif ($view === 'signatures'): ?>
        <?php
        $statusLabels = ['off' => t('Off'), 'observe' => t('Observe only'), 'shadow' => t('Shadow'), 'on' => t('On')];
        $statusTones = ['off' => 'neutral', 'observe' => 'warning', 'shadow' => 'warning', 'on' => 'positive'];
        $q = $context['q'] ?? '';
        $statusFilter = $context['status'] ?? '';
        $rule = $signatures[$context['rule'] ?? ''] ?? null;
        $filters = ['q' => $q, 'status' => $statusFilter];
        $filtered = array_filter($signatures, static fn ($item) =>
            ($statusFilter === '' || $item['status'] === $statusFilter)
            && ($q === '' || mb_stripos($item['id'] . ' ' . $item['label'], $q, 0, 'UTF-8') !== false));
        ?>
        <div class="master-detail<?= $rule !== null ? ' with-inspector' : '' ?>">
          <section class="panel master">
            <div class="section-head"><h2><?= h(t('Firewall Signatures')) ?></h2><span class="subtle"><?= h(t('%d signatures', count($filtered))) ?></span></div>
            <form method="get" class="filterbar" aria-label="<?= h(t('Signature filters')) ?>">
              <?php hidden('view', 'signatures'); ?>
              <label class="filter-search"><?= h(t('Search')) ?><input name="q" value="<?= h($q) ?>" maxlength="64" placeholder="<?= h(t('ID or description')) ?>"></label>
              <label><?= h(t('Status')) ?><select name="status"><option value=""><?= h(t('All')) ?></option>
                <?php foreach ($statusLabels as $key => $label): ?><option value="<?= h($key) ?>"<?= $statusFilter === $key ? ' selected' : '' ?>><?= h($label) ?></option><?php endforeach; ?>
              </select></label>
              <button class="button secondary" type="submit"><?= h(t('Apply')) ?></button>
              <?php if ($q !== '' || $statusFilter !== ''): ?><a class="button quiet" href="?view=signatures"><?= h(t('Clear')) ?></a><?php endif; ?>
            </form>
            <div class="table-wrap">
              <table class="policy-table">
                <thead><tr><th scope="col"><?= h(t('ID')) ?></th><th scope="col"><?= h(t('Description')) ?></th><th scope="col"><?= h(t('Score')) ?></th><th scope="col"><?= h(t('Status')) ?></th><th scope="col"><?= h(t('Actions')) ?></th></tr></thead>
                <tbody>
                  <?php foreach ($filtered as $item): ?>
                    <tr<?= $rule !== null && $rule['id'] === $item['id'] ? ' class="selected-row"' : '' ?>>
                      <td><bdi class="mono"><?= h($item['id']) ?></bdi></td>
                      <td><bdi><?= h(t($item['label'])) ?></bdi></td>
                      <td><bdi class="mono"><?= (int) $item['score'] ?></bdi></td>
                      <td><?php statusLabel($statusLabels[$item['status']], $statusTones[$item['status']]); ?></td>
                      <td><a class="text-link" href="<?= h(viewUrl('signatures', ['rule' => $item['id']] + $filters)) ?>"><?= h(t('Change status')) ?></a></td>
                    </tr>
                  <?php endforeach; ?>
                  <?php if ($filtered === []): ?><tr><td class="empty" colspan="5"><?= h(t('No signatures match this filter.')) ?></td></tr><?php endif; ?>
                </tbody>
              </table>
            </div>
          </section>
          <?php if ($rule !== null): ?>
            <aside class="panel inspector" aria-label="<?= h(t('Signature Settings')) ?>">
              <div class="section-head"><h2><?= h(t('Signature Settings')) ?></h2><a class="text-link" href="<?= h(viewUrl('signatures', $filters)) ?>"><?= h(t('Close')) ?></a></div>
              <div class="inspector-content">
                <dl class="facts">
                  <dt><?= h(t('ID')) ?></dt><dd><bdi class="mono"><?= h($rule['id']) ?></bdi></dd>
                  <dt><?= h(t('Description')) ?></dt><dd><bdi><?= h(t($rule['label'])) ?></bdi></dd>
                  <dt><?= h(t('Score')) ?></dt><dd><bdi class="mono"><?= (int) $rule['score'] ?></bdi></dd>
                  <dt><?= h(t('Status')) ?></dt><dd><?php statusLabel($statusLabels[$rule['status']], $statusTones[$rule['status']]); ?></dd>
                </dl>
                <?php if ($rule['score'] === 0): ?><p class="subtle inspector-note"><?= h(t('This signature records events only.')) ?></p><?php endif; ?>
                <form method="post" class="stack signature-form">
                  <?php formAction('signature'); hidden('signature', $rule['id']); hidden('target', $rule['status'] === 'off' ? 'on' : 'off'); ?>
                  <?php passwordField(); ?>
                  <button type="submit" class="button <?= $rule['status'] === 'off' ? 'primary' : 'secondary' ?>"><?= $rule['status'] === 'off' ? t('Enable signature') : t('Disable signature') ?></button>
                </form>
              </div>
            </aside>
          <?php endif; ?>
        </div>
      <?php elseif ($view === 'exceptions'): ?>
        <?php
        $exception = null;
        foreach ($exceptions as $item) {
            if ($item['id'] === ($context['exception'] ?? '')) {
                $exception = $item;
                break;
            }
        }
        ?>
        <div class="master-detail<?= $exception !== null ? ' with-inspector' : '' ?>">
          <section class="panel master">
            <div class="section-head"><h2><?= h(t('Configured Exceptions')) ?></h2><a class="button secondary" href="?view=attacks&amp;decision=block"><?= h(t('Add from log')) ?></a></div>
            <div class="table-wrap">
              <table class="policy-table">
                <thead><tr><th scope="col"><?= h(t('Rule')) ?></th><th scope="col"><?= h(t('Request')) ?></th><th scope="col"><?= h(t('Field')) ?></th><th scope="col"><?= h(t('Expires (UTC)')) ?></th><th scope="col"><?= h(t('Status')) ?></th><th scope="col"><?= h(t('Details')) ?></th></tr></thead>
                <tbody>
                <?php foreach ($exceptions as $item): $expired = $item['expires'] <= time(); ?>
                  <tr<?= $exception !== null && $exception['id'] === $item['id'] ? ' class="selected-row"' : '' ?>>
                    <td><bdi class="mono"><?= h($item['rule']) ?></bdi></td>
                    <td><bdi class="mono"><?= h($item['method'] . ' ' . $item['path']) ?></bdi></td>
                    <td><bdi class="mono"><?= h($item['source'] . ' ' . $item['field']) ?></bdi></td>
                    <td class="nowrap"><bdi class="mono"><?= h(gmdate('Y-m-d H:i', (int) $item['expires'])) ?></bdi></td>
                    <td><?php statusLabel($expired ? t('Expired') : t('Active'), $expired ? 'neutral' : 'positive'); ?></td>
                    <td><a class="text-link" href="<?= h(viewUrl('exceptions', ['exception' => $item['id']])) ?>"><?= h(t('View')) ?></a></td>
                  </tr>
                <?php endforeach; ?>
                <?php if ($exceptions === []): ?><tr><td class="empty" colspan="6"><?= h(t('No exceptions have been added.')) ?></td></tr><?php endif; ?>
                </tbody>
              </table>
            </div>
          </section>
          <?php if ($exception !== null): ?>
            <aside class="panel inspector" aria-label="<?= h(t('Exception Details')) ?>">
              <div class="section-head"><h2><?= h(t('Exception Details')) ?></h2><a class="text-link" href="?view=exceptions"><?= h(t('Close')) ?></a></div>
              <div class="inspector-content">
                <dl class="facts">
                  <dt><?= h(t('Rule')) ?></dt><dd><bdi class="mono"><?= h($exception['rule']) ?></bdi></dd>
                  <dt><?= h(t('Request')) ?></dt><dd><bdi class="mono"><?= h($exception['method'] . ' ' . $exception['path']) ?></bdi></dd>
                  <dt><?= h(t('Field')) ?></dt><dd><bdi class="mono"><?= h($exception['source'] . ' ' . $exception['field']) ?></bdi></dd>
                  <dt><?= h(t('Source event')) ?></dt><dd><a class="text-link" href="<?= h(viewUrl('attacks', ['event' => $exception['reference']])) ?>"><bdi class="mono"><?= h($exception['reference']) ?></bdi></a></dd>
                </dl>
                <form method="post" class="stack"><?php formAction('remove-exception'); hidden('id', $exception['id']); ?>
                  <?php passwordField(); ?><button class="button danger" type="submit"><?= h(t('Remove exception')) ?></button>
                </form>
              </div>
            </aside>
          <?php endif; ?>
        </div>
      <?php else: ?>
        <div class="dashboard-columns access-columns">
          <section class="panel">
            <div class="section-head"><h2><?= h(t('Login IP Restrictions')) ?></h2><?php statusLabel($auth['trusted'] === [] ? t('No IP restrictions') : t('Allowlist enabled'), $auth['trusted'] === [] ? 'neutral' : 'positive'); ?></div>
            <div class="form-content">
              <p class="subtle"><?= h(t('Session IP')) ?> <bdi class="mono"><?= h($ip) ?></bdi><?= h(t('. Enter one IP or CIDR per line. An empty list allows all IPs.')) ?></p>
              <form method="post" class="stack"><?php formAction('trusted-hosts'); ?>
                <label><?= h(t('Allowed IPs')) ?><textarea name="trusted" rows="4" maxlength="4096" dir="ltr" placeholder="<?= h(t('No IP restrictions')) ?>"><?= h(implode("\n", $auth['trusted'])) ?></textarea></label>
                <?php passwordField(); ?><button class="button primary" type="submit"><?= h(t('Save allowlist')) ?></button>
              </form>
            </div>
          </section>
          <section class="panel">
            <div class="section-head"><h2><?= h(t('Administrator Account')) ?></h2></div>
            <form method="post" class="stack form-content"><?php formAction('credentials'); ?>
              <label><?= h(t('Username')) ?><input name="username" type="text" value="<?= h($auth['username']) ?>" autocomplete="username" maxlength="40" dir="ltr" required></label>
              <label><?= h(t('New password')) ?><input name="new_password" type="password" autocomplete="new-password" minlength="16" maxlength="72" required></label>
              <label><?= h(t('Confirm new password')) ?><input name="confirm_password" type="password" autocomplete="new-password" minlength="16" maxlength="72" required></label>
              <?php passwordField(); ?><button class="button primary" type="submit"><?= h(t('Update credentials')) ?></button>
            </form>
          </section>
        </div>
        <section class="panel">
          <div class="section-head"><h2><?= h(t('Administrator Activity')) ?></h2></div>
          <div class="table-wrap">
            <table class="policy-table">
              <thead><tr><th scope="col"><?= h(t('Time (UTC)')) ?></th><th scope="col"><?= h(t('Actions')) ?></th><th scope="col"><?= h(t('Administrator')) ?></th><th scope="col">IP</th></tr></thead>
              <tbody>
                <?php foreach ($audit as $row): ?>
                  <tr><td><bdi class="mono"><?= h(utcTime((string) ($row['time'] ?? ''))) ?></bdi></td><td><bdi><?= h(t($row['action'] ?? '-')) ?></bdi></td><td><bdi><?= h($row['actor'] ?? '-') ?></bdi></td><td><bdi class="mono"><?= h($row['ip'] ?? '-') ?></bdi></td></tr>
                <?php endforeach; ?>
                <?php if ($audit === []): ?><tr><td class="empty" colspan="4"><?= h(t('No activity has been recorded.')) ?></td></tr><?php endif; ?>
              </tbody>
            </table>
          </div>
        </section>
      <?php endif; ?>
    </main>
  </div>
</div>
<?php endif; ?>
</body>
</html>
