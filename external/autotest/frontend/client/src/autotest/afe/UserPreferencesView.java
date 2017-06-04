package autotest.afe;

import autotest.common.JsonRpcCallback;
import autotest.common.JsonRpcProxy;
import autotest.common.StaticDataRepository;
import autotest.common.StaticDataRepository.FinishedCallback;
import autotest.common.Utils;
import autotest.common.ui.TabView;
import autotest.common.ui.ToolTip;

import com.google.gwt.event.dom.client.ClickEvent;
import com.google.gwt.event.dom.client.ClickHandler;
import com.google.gwt.json.client.JSONBoolean;
import com.google.gwt.json.client.JSONObject;
import com.google.gwt.json.client.JSONString;
import com.google.gwt.json.client.JSONValue;
import com.google.gwt.user.client.ui.Button;
import com.google.gwt.user.client.ui.CheckBox;
import com.google.gwt.user.client.ui.FlexTable;
import com.google.gwt.user.client.ui.HTMLTable;
import com.google.gwt.user.client.ui.ListBox;
import com.google.gwt.user.client.ui.Panel;
import com.google.gwt.user.client.ui.VerticalPanel;
import com.google.gwt.user.client.ui.Widget;

public class UserPreferencesView extends TabView implements ClickHandler {
    private static final StaticDataRepository staticData = StaticDataRepository.getRepository();
    private static final JsonRpcProxy proxy = JsonRpcProxy.getProxy();

    public static interface UserPreferencesListener {
        public void onPreferencesChanged();
    }

    private JSONObject user;
    private UserPreferencesListener listener;

    private RadioChooser rebootBefore = new RadioChooser();
    private RadioChooser rebootAfter = new RadioChooser();
    private ListBox droneSet = new ListBox();
    private CheckBox showExperimental = new CheckBox();
    private Button saveButton = new Button("Save preferences");
    private HTMLTable preferencesTable = new FlexTable();

    public UserPreferencesView(UserPreferencesListener listener) {
        this.listener = listener;
    }

    @Override
    public String getElementId() {
        return "user_preferences";
    }

    @Override
    public void initialize() {
        super.initialize();

        RadioChooserDisplay rebootBeforeDisplay = new RadioChooserDisplay();
        RadioChooserDisplay rebootAfterDisplay = new RadioChooserDisplay();
        rebootBefore.bindDisplay(rebootBeforeDisplay);
        rebootAfter.bindDisplay(rebootAfterDisplay);

        Panel container = new VerticalPanel();
        AfeUtils.populateRadioChooser(rebootBefore, "reboot_before");
        AfeUtils.populateRadioChooser(rebootAfter, "reboot_after");

        saveButton.addClickHandler(this);

        ToolTip rebootBeforeToolTip = new ToolTip(
            "?",
            "Reboots all assigned hosts before the job runs. " +
            "Click If dirty to reboot the host only if it hasn’t been rebooted " +
            "since it was added, locked, or after running the last job.");
        ToolTip rebootAfterToolTip = new ToolTip(
            "?",
            "Reboots all assigned hosts after the job runs. Click If all tests passed " +
            "to skip rebooting the host if any test in the job fails.");
        ToolTip showExperimentalToolTip = new ToolTip(
            "?",
            "Make the Create Job page show tests that are " +
            "marked as \"experimental\" in the control file");

        addOption("Default reboot before value", rebootBeforeDisplay, rebootBeforeToolTip);
        addOption("Default reboot after value", rebootAfterDisplay, rebootAfterToolTip);
        addOption("Show experimental tests", showExperimental, showExperimentalToolTip);
        if (staticData.getData("drone_sets_enabled").isBoolean().booleanValue()) {
            AfeUtils.populateListBox(droneSet, "drone_sets");
            addOption("Drone set", droneSet);
        }

        container.add(preferencesTable);
        container.add(saveButton);
        addWidget(container, "user_preferences_table");
    }

    @Override
    public void refresh() {
        staticData.refresh(new FinishedCallback() {
            public void onFinished() {
                user = staticData.getData("current_user").isObject();
                updateValues();
                if (listener != null) {
                    listener.onPreferencesChanged();
                }
            }
        });
    }

    private void updateValues() {
        rebootBefore.setSelectedChoice(getValue("reboot_before"));
        rebootAfter.setSelectedChoice(getValue("reboot_after"));
        AfeUtils.setSelectedItem(droneSet, getValue("drone_set"));

        showExperimental.setValue(user.get("show_experimental").isBoolean().booleanValue());
    }

    private String getValue(String key) {
        return Utils.jsonToString(user.get(key));
    }

    public void onClick(ClickEvent event) {
        assert event.getSource() == saveButton;
        saveValues();
    }

    private void saveValues() {
        JSONObject values = new JSONObject();
        values.put("id", user.get("id"));
        values.put("reboot_before", new JSONString(rebootBefore.getSelectedChoice()));
        values.put("reboot_after", new JSONString(rebootAfter.getSelectedChoice()));
        if (staticData.getData("drone_sets_enabled").isBoolean().booleanValue()) {
          values.put("drone_set", new JSONString(droneSet.getItemText(droneSet.getSelectedIndex())));
        }
        values.put("show_experimental", JSONBoolean.getInstance(showExperimental.getValue()));
        proxy.rpcCall("modify_user", values, new JsonRpcCallback() {
            @Override
            public void onSuccess(JSONValue result) {
                refresh();
            }
        });
    }

    private void addOption(String name, Widget widget) {
        int row = preferencesTable.getRowCount();
        preferencesTable.setText(row, 0, name);
        preferencesTable.setWidget(row, 1, widget);
    }

    private void addOption(String name, Widget widget, Widget extraWidget) {
        int row = preferencesTable.getRowCount();
        preferencesTable.setText(row, 0, name);
        preferencesTable.setWidget(row, 1, widget);
        preferencesTable.setWidget(row, 2, extraWidget);
    }
}
