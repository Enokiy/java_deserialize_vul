package com.github.enokiy;

public class Employee extends User{
    private int eid;

    public Employee() {
        System.out.println("Employee constructor is called!!");
    }

    public void setEid(int eid) {
        System.out.println("Employee setEid is called!!");
        this.eid = eid;
    }
    public int getEid() {
        System.out.println("Employee getEid is called!!");
        return eid;
    }
}
