# Stored Injection RCE via Message Template → Groovy/FreeMarker Evaluation

## Project Information
- **Project:** dromara/lamp-cloud
- **Type:** Stored Injection RCE (Template Injection + Code Evaluation)
- **Severity:** Critical (CVSS 9.1)
- **CWE:** CWE-94 (Code Injection), CWE-1336 (Improper Neutralization of Special Elements)

## Vulnerability Description

dromara lamp-cloud contains a stored injection vulnerability where message template content is stored via JPA and later evaluated as Groovy code or FreeMarker templates. Three independent attack surfaces allow RCE:

1. **DefMsgTemplate.script → Groovy RCE**: The `script` field in message templates is evaluated via `GroovyClassLoader.parseClass()` + `InvokerHelper.createScript().run()`
2. **DefMsgTemplate.content → FreeMarker SSTI**: The `content` field is processed by FreeMarker with `BeansWrapper` providing static model access
3. **DefInterface.script → Groovy RCE**: Interface definitions with `execMode=SCRIPT` evaluate Groovy code with Spring bean injection

## Data Flow

### Attack Surface 1: DefMsgTemplate.script → Groovy RCE

**Write Path:**
- File: `lamp-system/lamp-system-controller/.../DefMsgTemplateController.java:43-46`
- Admin POSTs to `POST /defMsgTemplate` with `DefMsgTemplateSaveVO` containing arbitrary Groovy code in `script` field
- `DefMsgTemplateServiceImpl.saveBefore()` (lines 87-93) only validates code uniqueness — NO script content validation

**Read/Eval Path:**
- `MsgBiz.execSend()` loads template from DB → `MsgStrategy.replaceVariable()` (lines 66-68)
- Calls `GlueFactory.getInstance().exeGroovyScript(script, params)`
- `GlueFactory.exeGroovyScript()` (lines 92-100): `GroovyClassLoader.parseClass()` → `InvokerHelper.createScript(clazz, new Binding(params)).run()`

### Attack Surface 2: DefInterface.script → Groovy RCE with Spring Beans

**Write Path:**
- File: `lamp-system/lamp-system-controller/.../DefInterfaceController.java:43-46`
- Admin POSTs to `POST /defInterface` with `DefInterfaceSaveVO` where `execMode="02"` and `script` = Groovy payload

**Read/Eval Path:**
- `MsgContext.execSend()` (lines 84-91): `GlueFactory.getInstance().loadNewInstance(defInterface.getScript())`
- `SpringGlueFactory` injects `@Autowired`/`@Resource` Spring beans into Groovy instance
- Full Spring ApplicationContext available to attacker code

### Attack Surface 3: DefMsgTemplate.content → FreeMarker SSTI

**Write Path:** Same as Surface 1, using `content` field (longtext in MySQL)

**Read/Eval Path:**
- `FreeMarkerUtil.generateString()` uses `BeansWrapper` with static model access
- `SpringUtils`, `DateUtils`, `BeanPlusUtil` exposed as shared variables
- `TemplateClassResolver.SAFER` NOT configured — `?new` built-in may be available

## Key Evidence

**No script sanitization** (`DefMsgTemplateServiceImpl.java:87-93`):
```java
protected <SaveVO> DefMsgTemplate saveBefore(SaveVO saveVO) {
    DefMsgTemplateSaveVO extendMsgTemplateSaveVO = (DefMsgTemplateSaveVO) saveVO;
    ArgumentAssert.isFalse(...check code uniqueness..., "模板标识{}已存在", ...);
    extendMsgTemplateSaveVO.setParam(getParamByContent(...));
    return super.saveBefore(extendMsgTemplateSaveVO);  // NO script validation
}
```

**Groovy eval with no sandbox** (`GlueFactory.java:92-100`):
```java
public Object exeGroovyScript(String script, Map<String, Object> params) {
    Class<?> clazz = getCodeSourceClass(script);
    return InvokerHelper.createScript(clazz, new Binding(params)).run();
}
```

**FreeMarker with BeansWrapper static access** (`FreeMarkerUtil.java:46-68`):
```java
BeansWrapper wrapper = new BeansWrapper(Configuration.VERSION_2_3_30);
TemplateHashModel staticModels = wrapper.getStaticModels();
FREEMARKER_CFG.setSharedVariable("SpringUtils", (TemplateHashModel) staticModels.get("top.tangyh.basic.utils.SpringUtils"));
```

## Authentication

Authentication is required (OAuth via lamp-gateway). However:
- Template CRUD requires admin-level permissions
- Message send requires any authenticated employee (`@LoginUser(isEmployee = true)`)
- Write and trigger can be performed by different users (privilege escalation scenario)

## Remediation

1. **Groovy Sandbox:** Use `GroovyClassLoader` with a `CompilerConfiguration` that restricts dangerous operations
2. **Script Allowlisting:** Validate script content against approved patterns; reject arbitrary code
3. **FreeMarker Hardening:** Set `Configuration.setNewBuiltinClassResolver(TemplateClassResolver.SAFER)` and remove `BeansWrapper` static model access
4. **Separate Privileges:** Require elevated permissions for script-containing fields specifically
5. **Content Security Policy:** Sanitize template content to prevent injection of code constructs
