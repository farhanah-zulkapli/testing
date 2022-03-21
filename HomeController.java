package my.gov.ns.ptgns.e.controller;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import my.gov.ns.ptgns.e.enumeration.SkhtApiKey;
import my.gov.ns.ptgns.e.enumeration.SkhtApiUrlPath;
import my.gov.ns.ptgns.e.model.*;
import my.gov.ns.ptgns.e.utils.HttpRequest;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.sql.DataSource;
import java.util.ArrayList;
import java.util.List;

@Controller
public class HomeController {

    private static final Logger LOGGER = LoggerFactory.getLogger(HomeController.class);

    @Autowired
    private Environment env;

    @Autowired
    private HttpServletRequest request;

    @Autowired
    private DataSource dataSource;

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String home(Model model, RedirectAttributes redirectAttributes) {
        // GET SESSION AKAUN
        Akaun akaun = (Akaun) request.getSession().getAttribute("akaun");
        if (env.getProperty("sys.maintenance").equalsIgnoreCase("true")) {
            if (akaun != null) {
                if (akaun.getKOD_STATUS().equalsIgnoreCase("02")) {
                    // CHECK BIO UPDATED
                    RujPenyampai rujPenyampai = new RujPenyampai();
                    Gson gson = new Gson();
                    JSONObject responseBody = new HttpRequest().get(env, SkhtApiKey.SAPI, SkhtApiUrlPath.SAPI_UTIL_REGISTER_CHECK_REP.getPath_url() + "/" + akaun.getNO_KP());
                    if (responseBody != null) {
                        rujPenyampai = gson.fromJson(responseBody.getJSONObject("penyampai").toString(), RujPenyampai.class);
                    }

                    // CHOOSE TO UPDATE
                    if (rujPenyampai.getPY_NOKP() != null) {
                        responseBody = new HttpRequest().get(env, SkhtApiKey.PAPI, SkhtApiUrlPath.PAPI_USER_EXTERNAL_BIO.generatePath(akaun.getID(), rujPenyampai.getPY_KOD()));
                        if (responseBody != null) {
                            if (responseBody.getString("status").equalsIgnoreCase("success")) {
                                return "home/bio_success";
                            } else {
                                redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
                                return "redirect:/error";
                            }
                        } else {
                            redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
                            return "redirect:/error";
                        }
                    } else {
                        String sysMode = env.getProperty("sys.mode");
                        String apiKey = env.getProperty("sys.api.key.system." + sysMode);
                        model.addAttribute("apiKey", apiKey);
                        model.addAttribute("apiPathResendEmail", env.getProperty("sys.skhtnode.url." + sysMode) + SkhtApiUrlPath.PAPI_USER_EXTERNAL_VERIFY_RESEND.generatePath(akaun.getVERIFICATION_CODE()));
                        model.addAttribute("activeTab", "dashboard");
                        return "home/dashboard";
                    }
                } else {
                    String sysMode = env.getProperty("sys.mode");
                    String apiKey = env.getProperty("sys.api.key.system." + sysMode);
                    model.addAttribute("apiKey", apiKey);
                    model.addAttribute("apiPathResendEmail", env.getProperty("sys.skhtnode.url." + sysMode) + SkhtApiUrlPath.PAPI_USER_EXTERNAL_VERIFY_RESEND.generatePath(akaun.getVERIFICATION_CODE()));
                    model.addAttribute("activeTab", "dashboard");
                    return "home/dashboard";
                }
            } else {
                return "home/maintanence";
            }
        } else {
            if (akaun != null) {
                if (akaun.getKOD_STATUS().equalsIgnoreCase("02")) {
                    // CHECK BIO UPDATED
                    RujPenyampai rujPenyampai = new RujPenyampai();
                    Gson gson = new Gson();
                    JSONObject responseBody = new HttpRequest().get(env, SkhtApiKey.SAPI, SkhtApiUrlPath.SAPI_UTIL_REGISTER_CHECK_REP.getPath_url() + "/" + akaun.getNO_KP());
                    if (responseBody != null) {
                        rujPenyampai = gson.fromJson(responseBody.getJSONObject("penyampai").toString(), RujPenyampai.class);
                    }

                    // CHOOSE TO UPDATE
                    if (rujPenyampai.getPY_NOKP() != null) {
                        responseBody = new HttpRequest().get(env, SkhtApiKey.PAPI, SkhtApiUrlPath.PAPI_USER_EXTERNAL_BIO.generatePath(akaun.getID(), rujPenyampai.getPY_KOD()));
                        if (responseBody != null) {
                            if (responseBody.getString("status").equalsIgnoreCase("success")) {
                                return "home/bio_success";
                            } else {
                                redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
                                return "redirect:/error";
                            }
                        } else {
                            redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
                            return "redirect:/error";
                        }
                    } else {
                        String sysMode = env.getProperty("sys.mode");
                        String apiKey = env.getProperty("sys.api.key.system." + sysMode);
                        model.addAttribute("apiKey", apiKey);
                        model.addAttribute("apiPathResendEmail", env.getProperty("sys.skhtnode.url." + sysMode) + SkhtApiUrlPath.PAPI_USER_EXTERNAL_VERIFY_RESEND.generatePath(akaun.getVERIFICATION_CODE()));
                        model.addAttribute("activeTab", "dashboard");
                        return "home/dashboard";
                    }
                } else {
                    String sysMode = env.getProperty("sys.mode");
                    String apiKey = env.getProperty("sys.api.key.system." + sysMode);
                    model.addAttribute("apiKey", apiKey);
                    model.addAttribute("apiPathResendEmail", env.getProperty("sys.skhtnode.url." + sysMode) + SkhtApiUrlPath.PAPI_USER_EXTERNAL_VERIFY_RESEND.generatePath(akaun.getVERIFICATION_CODE()));
                    model.addAttribute("activeTab", "dashboard");
                    return "home/dashboard";
                }
            } else {
                Gson gson = new Gson();
                JSONObject responseBody = new HttpRequest().get(env, SkhtApiKey.SAPI, SkhtApiUrlPath.SAPI_UTIL_OFFICE_HOUR.getPath_url());
                if (responseBody != null) {
                    List<RujMasaPejabat> rujMasaPejabats = gson.fromJson(responseBody.getJSONArray("masaPejabats").toString(), new TypeToken<ArrayList<RujMasaPejabat>>() {
                    }.getType());
                    model.addAttribute("rujMasaPejabats", rujMasaPejabats);
                }
                return "home/landing";
            }
        }
    }

    @RequestMapping(value = "/login", method = RequestMethod.GET)
    public String login(Model model, @RequestParam(name = "authentication", required = false) String authentication, RedirectAttributes redirectAttributes) {
        Gson gson = new Gson();
        JSONObject responseBody = new HttpRequest().get(env, SkhtApiKey.SAPI, SkhtApiUrlPath.SAPI_UTIL_OFFICE_HOUR.getPath_url());
        if (responseBody != null) {
            List<RujMasaPejabat> rujMasaPejabats = gson.fromJson(responseBody.getJSONArray("masaPejabats").toString(), new TypeToken<ArrayList<RujMasaPejabat>>() {
            }.getType());
            model.addAttribute("rujMasaPejabats", rujMasaPejabats);
            if (authentication != null) {
                model.addAttribute("error", "true");
            }
            return "home/login";
        } else {
            redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
            return "redirect:/error";
        }
    }

    @RequestMapping(value = "/register", method = RequestMethod.GET)
    public String register(Model model, RedirectAttributes redirectAttributes) {
        Gson gson = new Gson();
        JSONObject responseBody = new HttpRequest().get(env, SkhtApiKey.SAPI, SkhtApiUrlPath.SAPI_UTIL_REGISTER.getPath_url());
        if (responseBody != null) {
            List<RujAkaunPeranan> rujAkaunPeranans = gson.fromJson(responseBody.getJSONArray("akaunPeranans").toString(), new TypeToken<ArrayList<RujAkaunPeranan>>() {
            }.getType());
            List<RujNegeri> rujNegeris = gson.fromJson(responseBody.getJSONArray("negeris").toString(), new TypeToken<ArrayList<RujNegeri>>() {
            }.getType());
            String sysMode = env.getProperty("sys.mode");
            String apiKey = env.getProperty("sys.api.key.system." + sysMode);
            model.addAttribute("apiKey", apiKey);
            model.addAttribute("apiPathRepCheck", env.getProperty("sys.skhtnode.url." + sysMode) + SkhtApiUrlPath.SAPI_UTIL_REGISTER_CHECK_REP.getPath_url());
            model.addAttribute("rujAkaunPeranans", rujAkaunPeranans);
            model.addAttribute("rujNegeris", rujNegeris);
            return "home/register";
        } else {
            redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
            return "redirect:/error";
        }
    }

    @RequestMapping(value = "/register/mobile", method = RequestMethod.GET)
    public String registerMobile(Model model, RedirectAttributes redirectAttributes) {
        Gson gson = new Gson();
        JSONObject responseBody = new HttpRequest().get(env, SkhtApiKey.SAPI, SkhtApiUrlPath.SAPI_UTIL_REGISTER.getPath_url());
        if (responseBody != null) {
            List<RujAkaunPeranan> rujAkaunPeranans = gson.fromJson(responseBody.getJSONArray("akaunPeranans").toString(), new TypeToken<ArrayList<RujAkaunPeranan>>() {
            }.getType());
            List<RujNegeri> rujNegeris = gson.fromJson(responseBody.getJSONArray("negeris").toString(), new TypeToken<ArrayList<RujNegeri>>() {
            }.getType());
            String sysMode = env.getProperty("sys.mode");
            String apiKey = env.getProperty("sys.api.key.system." + sysMode);
            model.addAttribute("apiKey", apiKey);
            model.addAttribute("apiPathRepCheck", env.getProperty("sys.skhtnode.url." + sysMode) + SkhtApiUrlPath.SAPI_UTIL_REGISTER_CHECK_REP.getPath_url());
            model.addAttribute("rujAkaunPeranans", rujAkaunPeranans);
            model.addAttribute("rujNegeris", rujNegeris);
            return "home/register_mobile";
        } else {
            redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
            return "redirect:/error";
        }
    }

    @RequestMapping(value = "/register", method = RequestMethod.POST)
    public String externalCreate(Model model, @RequestParam("name") String name, @RequestParam("email") String email,
                                 @RequestParam("phone") String phone, @RequestParam("ic") String ic,
                                 @RequestParam("type") String type, @RequestParam(value = "rep", required = false) String rep,
                                 @RequestParam("address1") String address1, @RequestParam("address2") String address2,
                                 @RequestParam(value = "address3", required = false) String address3,
                                 @RequestParam(value = "address4", required = false) String address4,
                                 @RequestParam("postcode") String postcode, @RequestParam("city") String city,
                                 @RequestParam("state") String state, @RequestParam("password") String password,
                                 RedirectAttributes redirectAttributes) {
        // FILL AKAUN
        Akaun akaun = new Akaun();
        akaun.setNAMA(name);
        akaun.setEMEL(email);
        akaun.setNO_TEL(phone);
        akaun.setNO_KP(ic);
        akaun.setKOD_PERANAN(type);
        akaun.setALAMAT1(address1);
        akaun.setALAMAT2(address2);
        akaun.setALAMAT3(address3);
        akaun.setALAMAT4(address4);
        akaun.setPOSKOD(postcode);
        akaun.setBANDAR(city);
        akaun.setNEGERI(state);
        akaun.setKATALALUAN(new BCryptPasswordEncoder().encode(password));
        akaun.setKOD_STATUS("01"); // DAFTAR 01 -> EMEL VERIFY 02 -> BIO 03
        akaun.setKODPY(rep);

        Gson gson = new Gson();
        JSONObject responseBody = new HttpRequest().get(env, SkhtApiKey.SAPI, SkhtApiUrlPath.SAPI_UTIL_REGISTER_CHECK.generatePath(email, ic));
        if (responseBody != null) {
            Akaun akaunExist = gson.fromJson(responseBody.getJSONObject("akaun").toString(), Akaun.class);
            if (akaunExist.getEMEL() == null) {
                // CREATE PUT BODY
                JSONObject jsonObject = new JSONObject();
                jsonObject.put("akaun", new JSONObject(new Gson().toJson(akaun)));

                responseBody = new HttpRequest().put(env, SkhtApiKey.PAPI, SkhtApiUrlPath.PAPI_USER_EXTERNAL_CREATE.getPath_url(), jsonObject);
                if (responseBody != null) {
                    if (responseBody.getString("status").equalsIgnoreCase("success")) {
                        return "home/register_success";
                    } else {
                        LOGGER.error("API - " + responseBody.getString("cause"));
                        redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
                        return "redirect:/error";
                    }
                } else {
                    redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
                    return "redirect:/error";
                }
            } else {
                responseBody = new HttpRequest().get(env, SkhtApiKey.SAPI, SkhtApiUrlPath.SAPI_UTIL_REGISTER.getPath_url());
                if (responseBody != null) {
                    List<RujAkaunPeranan> rujAkaunPeranans = gson.fromJson(responseBody.getJSONArray("akaunPeranans").toString(), new TypeToken<ArrayList<RujAkaunPeranan>>() {
                    }.getType());
                    List<RujNegeri> rujNegeris = gson.fromJson(responseBody.getJSONArray("negeris").toString(), new TypeToken<ArrayList<RujNegeri>>() {
                    }.getType());
                    model.addAttribute("error", "true");
                    model.addAttribute("akaun", akaun);
                    model.addAttribute("rujAkaunPeranans", rujAkaunPeranans);
                    model.addAttribute("rujNegeris", rujNegeris);
                    return "home/register";
                } else {
                    redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
                    return "redirect:/error";
                }
            }
        } else {
            redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
            return "redirect:/error";
        }
    }

    @RequestMapping(value = "/register/verify/{code}", method = RequestMethod.GET)
    public String verify(Model model, @PathVariable("code") String code, RedirectAttributes redirectAttributes) {
        JSONObject responseBody = new HttpRequest().get(env, SkhtApiKey.PAPI, SkhtApiUrlPath.PAPI_USER_EXTERNAL_VERIFY.generatePath(code));
        if (responseBody != null) {
            if (responseBody.getString("status").equalsIgnoreCase("success")) {
                return "home/verify";
            } else {
                LOGGER.error("API - " + responseBody.getString("cause"));
                model.addAttribute("error", "true");
                return "home/verify";
            }
        } else {
            redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
            return "redirect:/error";
        }
    }

    @RequestMapping(value = "/forgot-password", method = RequestMethod.GET)
    public String forgotPassword() {
        return "home/forgot_password";
    }

    @RequestMapping(value = "/forgot-password", method = RequestMethod.POST)
    public String forgotPassword(@RequestParam("email") String email, RedirectAttributes redirectAttributes) {

        // GET ACCOUNT INFO
        Akaun akaun = new Akaun();

        // REQUEST BODY
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("email", email);

        JSONObject responseBody = new HttpRequest().post(env, SkhtApiKey.SAPI, SkhtApiUrlPath.SAPI_USER_BY_EMAIL.getPath_url(), jsonObject);
        if (responseBody != null) {
            Gson gson = new Gson();
            akaun = gson.fromJson(responseBody.getJSONObject("akaun").toString(), Akaun.class);
        }

        responseBody = new HttpRequest().get(env, SkhtApiKey.PAPI, SkhtApiUrlPath.PAPI_USER_PASSWORD_FORGOT.generatePath(akaun.getID()));
        if (responseBody != null) {
            if (responseBody.getString("status").equalsIgnoreCase("success")) {
                return "home/forgot_password_success";
            } else {
                LOGGER.error("API - " + responseBody.getString("cause"));
                redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
                return "redirect:/error";
            }
        } else {
            redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
            return "redirect:/error";
        }
    }

    @RequestMapping(value = "/new-password/{code}", method = RequestMethod.GET)
    public String newPassword(Model model, @PathVariable("code") String code, RedirectAttributes redirectAttributes) {
        JSONObject responseBody = new HttpRequest().get(env, SkhtApiKey.PAPI, SkhtApiUrlPath.PAPI_USER_PASSWORD_VERIFY.generatePath(code));
        if (responseBody != null) {
            if (responseBody.getString("status").equalsIgnoreCase("success")) {
                model.addAttribute("code", code);
                return "home/new_password";
            } else {
                LOGGER.error("API - " + responseBody.getString("cause"));
                model.addAttribute("error", "true");
                return "home/new_password";
            }
        } else {
            redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
            return "redirect:/error";
        }
    }

    @RequestMapping(value = "/new-password", method = RequestMethod.POST)
    public String newPassword(@RequestParam("code") String code, @RequestParam("password") String password, RedirectAttributes redirectAttributes) {
        // GET ACCOUNT INFO
        Akaun akaun = new Akaun();

        // REQUEST BODY
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("verificationCode", code);

        JSONObject responseBody = new HttpRequest().post(env, SkhtApiKey.SAPI, SkhtApiUrlPath.SAPI_USER_BY_VERIFICATION_CODE.getPath_url(), jsonObject);
        if (responseBody != null) {
            Gson gson = new Gson();
            akaun = gson.fromJson(responseBody.getJSONObject("akaun").toString(), Akaun.class);
        }

        akaun.setKATALALUAN(new BCryptPasswordEncoder().encode(password));

        // CREATE PUT BODY
        jsonObject = new JSONObject();
        jsonObject.put("akaun", new JSONObject(new Gson().toJson(akaun)));

        responseBody = new HttpRequest().put(env, SkhtApiKey.PAPI, SkhtApiUrlPath.PAPI_USER_PASSWORD_UPDATE.getPath_url(), jsonObject);
        if (responseBody != null) {
            if (responseBody.getString("status").equalsIgnoreCase("success")) {
                return "home/new_password_success";
            } else {
                LOGGER.error("API - " + responseBody.getString("cause"));
                redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
                return "redirect:/error";
            }
        } else {
            redirectAttributes.addFlashAttribute("errorMessage", "Sila hubungi admin sistem untuk pertanyaan lanjut");
            return "redirect:/error";
        }
    }

    @RequestMapping(value = "/error", method = RequestMethod.GET)
    public String error() {
        return "exception/error";
    }

    @RequestMapping(value = "/myptgns/pp", method = RequestMethod.GET)
    public String pp() {
        return "home/pp";
    }

    @RequestMapping(value = "/myptgns/tnc", method = RequestMethod.GET)
    public String tnc() {
        return "home/tnc";
    }
    
    @RequestMapping(value = "/myptgns/mobile", method = RequestMethod.GET)
    public String mobile() {
        return "home/mobile";
    }
}
